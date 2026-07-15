import struct
from core.data_source import DataSource
from core.partition_manager import Partition
from core.utils import parse_dos_time

class FATBootSectorParser:
    """
    Analizador del Boot Sector para particiones FAT32.
    Proporciona metadatos fundamentales como clústeres, tamaño de la FAT y directorio raíz.
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.bytes_per_sector = 0
        self.sectors_per_cluster = 0
        self.reserved_sectors = 0
        self.num_fats = 0
        self.sectors_per_fat = 0
        self.root_cluster = 0
        self.root_entry_count = 0
        self.root_dir_sectors = 0
        self.fat_type = 32 # Por defecto FAT32
        
        self._parse_boot_sector()

    def _parse_boot_sector(self):
        # Leer el sector de arranque (VBR)
        self.raw_boot = self.data_source.read(self.partition.start_offset, 512)
        if len(self.raw_boot) < 512:
            raise ValueError("No se pudo leer el sector de arranque de 512 bytes.")
            
        # FAT BPB (BIOS Parameter Block)
        self.bytes_per_sector = struct.unpack('<H', self.raw_boot[11:13])[0]
        self.sectors_per_cluster = struct.unpack('<B', self.raw_boot[13:14])[0]
        self.reserved_sectors = struct.unpack('<H', self.raw_boot[14:16])[0]
        self.num_fats = struct.unpack('<B', self.raw_boot[16:17])[0]
        self.root_entry_count = struct.unpack('<H', self.raw_boot[17:19])[0]
        
        # Sectores totales (16 bits u offset de 32 bits)
        total_sectors_16 = struct.unpack('<H', self.raw_boot[19:21])[0]
        total_sectors_32 = struct.unpack('<I', self.raw_boot[32:36])[0]
        total_sectors = total_sectors_16 if total_sectors_16 != 0 else total_sectors_32
        
        fat_size_16 = struct.unpack('<H', self.raw_boot[22:24])[0]
        
        # Sectores por FAT
        if fat_size_16 != 0:
            self.sectors_per_fat = fat_size_16
        else:
            self.sectors_per_fat = struct.unpack('<I', self.raw_boot[36:40])[0]

        # Sectores del Directorio Raíz fijo (para FAT12/16)
        self.root_dir_sectors = ((self.root_entry_count * 32) + (self.bytes_per_sector - 1)) // self.bytes_per_sector
        
        # Sectores de Datos y Conteo de Clústeres (Fórmula estándar de MS)
        data_sectors = total_sectors - (self.reserved_sectors + (self.num_fats * self.sectors_per_fat) + self.root_dir_sectors)
        count_of_clusters = 0
        if self.sectors_per_cluster > 0:
            count_of_clusters = data_sectors // self.sectors_per_cluster
            
        # Determinar tipo oficial
        if count_of_clusters < 4085:
            self.fat_type = 12
            self.root_cluster = 0  # Usamos 0 como indicador lógico de Root Dir Fijo
        elif count_of_clusters < 65525:
            self.fat_type = 16
            self.root_cluster = 0  # Usamos 0 como indicador lógico de Root Dir Fijo
        else:
            self.fat_type = 32
            self.root_cluster = struct.unpack('<I', self.raw_boot[44:48])[0]

    def get_fat_start_offset(self) -> int:
        """Retorna el offset absoluto donde comienza la File Allocation Table."""
        return self.partition.start_offset + (self.reserved_sectors * self.bytes_per_sector)

class FATParser:
    """
    Clase principal para analizar sistemas FAT (foco inicial FAT32).
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.boot_sector = FATBootSectorParser(data_source, partition)

    def get_info(self) -> dict:
        info = {
            "Bytes por sector": self.boot_sector.bytes_per_sector,
            "Sectores por clúster": self.boot_sector.sectors_per_cluster,
            "Sectores reservados": self.boot_sector.reserved_sectors,
            "Cantidad de FATs": self.boot_sector.num_fats,
            "Sectores por FAT": self.boot_sector.sectors_per_fat,
        }
        
        fat_size_bytes = self.boot_sector.sectors_per_fat * self.boot_sector.bytes_per_sector
        base_offset = self.boot_sector.get_fat_start_offset()
        
        for i in range(self.boot_sector.num_fats):
            fat_start = base_offset + (i * fat_size_bytes)
            info[f"Inicio FAT {i+1} (Offset absoluto)"] = f"{hex(fat_start)} (Sector/LBA: {fat_start // 512})"
            
        data_start = self.get_data_start_offset()
        info["Inicio Región de Datos"] = f"{hex(data_start)} (Sector/LBA: {data_start // 512})"
        
        return info

    def get_data_start_offset(self) -> int:
        """Calcula el inicio de la región de datos."""
        fat_size_bytes = self.boot_sector.num_fats * self.boot_sector.sectors_per_fat * self.boot_sector.bytes_per_sector
        root_dir_bytes = self.boot_sector.root_dir_sectors * self.boot_sector.bytes_per_sector
        return self.boot_sector.get_fat_start_offset() + fat_size_bytes + root_dir_bytes

    def get_cluster_offset(self, cluster_num: int) -> int:
        """Calcula el offset absoluto de un clúster en FAT."""
        if cluster_num < 2:
            raise ValueError("En FAT, los clústeres de datos empiezan a partir del número 2.")
        return self.get_data_start_offset() + ((cluster_num - 2) * self.get_cluster_size())

    def get_cluster_size(self) -> int:
        return self.boot_sector.sectors_per_cluster * self.boot_sector.bytes_per_sector

    def get_fat_chain(self, start_cluster: int) -> list:
        """
        Recorre la File Allocation Table (FAT12/FAT16/FAT32) para obtener todos los clústeres de una cadena.
        """
        chain = []
        current_cluster = start_cluster
        fat_start = self.boot_sector.get_fat_start_offset()
        
        # Límite de seguridad
        max_clusters = self.partition.size_in_bytes // self.get_cluster_size()
        
        while current_cluster >= 2 and len(chain) < max_clusters:
            chain.append(current_cluster)
            
            if self.boot_sector.fat_type == 32:
                entry_offset = fat_start + (current_cluster * 4)
                entry_data = self.data_source.read(entry_offset, 4)
                if not entry_data or len(entry_data) < 4:
                    break
                next_cluster = struct.unpack('<I', entry_data)[0]
                next_cluster &= 0x0FFFFFFF
                eof_marker = 0x0FFFFFF8
                bad_marker = 0x0FFFFFF7
            elif self.boot_sector.fat_type == 16:
                entry_offset = fat_start + (current_cluster * 2)
                entry_data = self.data_source.read(entry_offset, 2)
                if not entry_data or len(entry_data) < 2:
                    break
                next_cluster = struct.unpack('<H', entry_data)[0]
                eof_marker = 0xFFF8
                bad_marker = 0xFFF7
            else: # FAT12
                # Cada entrada es de 1.5 bytes. 
                # Calculamos el offset del byte que contiene el inicio de la entrada
                entry_offset = fat_start + ((current_cluster * 3) // 2)
                entry_data = self.data_source.read(entry_offset, 2)
                if not entry_data or len(entry_data) < 2:
                    break
                val = struct.unpack('<H', entry_data)[0]
                if current_cluster % 2 == 0:
                    next_cluster = val & 0x0FFF
                else:
                    next_cluster = val >> 4
                eof_marker = 0xFF8
                bad_marker = 0xFF7
                
            if next_cluster >= eof_marker: # EOF (End of File)
                break
            if next_cluster == bad_marker: # Clúster defectuoso
                break
            if next_cluster == 0: # Libre
                break
                
            current_cluster = next_cluster
            
        return chain

    def get_directory_entries(self, start_cluster: int) -> list:
        """
        Lee una cadena de clústeres correspondiente a un directorio y parsea sus entradas de 32 bytes,
        ensamblando nombres largos (VFAT).
        """
        entries = []
        
        # Leer todos los datos del directorio
        dir_data = bytearray()
        
        if start_cluster == 0 and self.boot_sector.fat_type in (12, 16):
            # Directorio raiz fijo de FAT12/16
            fat_size_bytes = self.boot_sector.num_fats * self.boot_sector.sectors_per_fat * self.boot_sector.bytes_per_sector
            root_offset = self.boot_sector.get_fat_start_offset() + fat_size_bytes
            root_size = self.boot_sector.root_entry_count * 32
            dir_data.extend(self.data_source.read(root_offset, root_size))
        else:
            chain = self.get_fat_chain(start_cluster)
            for cluster in chain:
                offset = self.get_cluster_offset(cluster)
                dir_data.extend(self.data_source.read(offset, self.get_cluster_size()))
            
        idx = 0
        lfn_buffer = {}
        
        while idx < len(dir_data):
            entry_bytes = dir_data[idx:idx+32]
            if len(entry_bytes) < 32:
                break
                
            first_byte = entry_bytes[0]
            if first_byte == 0x00:
                # Fin del directorio
                break
                
            attributes = entry_bytes[11]
            
            # Chequear si es una entrada VFAT (Long File Name)
            if attributes == 0x0F:
                sequence = first_byte & 0x1F # Enmascarar bit de borrado y último elemento
                # Extraer caracteres UTF-16 de los 3 bloques de la entrada LFN
                name_bytes = entry_bytes[1:11] + entry_bytes[14:26] + entry_bytes[28:32]
                try:
                    name_part = name_bytes.decode('utf-16le').split('\x00')[0] # Cortar en el primer nulo
                    lfn_buffer[sequence] = name_part
                except:
                    pass
            else:
                # Entrada 8.3 Estándar
                is_deleted = (first_byte == 0xE5)
                
                if first_byte == 0xE5:
                    # Restaurar el primer byte para el nombre si está borrado (temporal)
                    short_name_bytes = b'_' + entry_bytes[1:11]
                else:
                    short_name_bytes = entry_bytes[0:11]
                
                # Nombre corto (8.3)
                base_name = short_name_bytes[:8].decode('ascii', errors='ignore').strip()
                ext = short_name_bytes[8:].decode('ascii', errors='ignore').strip()
                short_name = f"{base_name}.{ext}" if ext else base_name
                
                # Nombre largo (ensamblar)
                long_name = ""
                if lfn_buffer:
                    # Ensamblar según el número de secuencia
                    for seq in sorted(lfn_buffer.keys()):
                        long_name += lfn_buffer[seq]
                    lfn_buffer.clear() # Limpiar para la siguiente entrada
                    
                final_name = long_name if long_name else short_name
                
                # Clúster de inicio
                cluster_high = struct.unpack('<H', entry_bytes[20:22])[0]
                cluster_low = struct.unpack('<H', entry_bytes[26:28])[0]
                start_cluster_file = (cluster_high << 16) | cluster_low
                
                file_size = struct.unpack('<I', entry_bytes[28:32])[0]
                is_dir = (attributes & 0x10) != 0
                
                # Fechas MS-DOS
                c_time = struct.unpack('<H', entry_bytes[14:16])[0]
                c_date = struct.unpack('<H', entry_bytes[16:18])[0]
                a_date = struct.unpack('<H', entry_bytes[18:20])[0]
                m_time = struct.unpack('<H', entry_bytes[22:24])[0]
                m_date = struct.unpack('<H', entry_bytes[24:26])[0]
                
                # Ignorar entradas "." y ".." para simplificar la salida
                if final_name not in (".", "..", "_       .   "):
                    entries.append(FATDirectoryEntry(
                        name=final_name,
                        is_directory=is_dir,
                        is_deleted=is_deleted,
                        size=file_size,
                        start_cluster=start_cluster_file,
                        attributes=attributes,
                        created=parse_dos_time(c_date, c_time),
                        modified=parse_dos_time(m_date, m_time),
                        accessed=parse_dos_time(a_date, 0)
                    ))
            
            idx += 32
            
        return entries

class FATDirectoryEntry:
    def __init__(self, name: str, is_directory: bool, is_deleted: bool, size: int, start_cluster: int, attributes: int,
                 created: str = "N/A", modified: str = "N/A", accessed: str = "N/A"):
        self.name = name
        self.is_directory = is_directory
        self.is_deleted = is_deleted
        self.size = size
        self.start_cluster = start_cluster
        self.attributes = attributes
        self.created = created
        self.modified = modified
        self.accessed = accessed
