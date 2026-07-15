import struct
from core.data_source import DataSource
from core.partition_manager import Partition
from core.utils import parse_dos_time

class exFATBootSectorParser:
    """
    Analizador del sector de arranque (VBR) para particiones exFAT.
    Mapea offsets oficiales segun la especificacion oficial de exFAT de Microsoft.
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        
        self.bytes_per_sector = 0
        self.sectors_per_cluster = 0
        self.fat_offset = 0
        self.fat_length = 0
        self.cluster_heap_offset = 0
        self.cluster_count = 0
        self.root_directory_cluster = 0
        self.volume_flags = 0
        
        self._parse_boot_sector()

    def _parse_boot_sector(self):
        # Leer el sector de arranque completo (512 bytes)
        self.raw_boot = self.data_source.read(self.partition.start_offset, 512)
        if len(self.raw_boot) < 512:
            raise ValueError("No se pudo leer el sector de arranque de exFAT.")

        # Validar la firma exFAT ("EXFAT   " en offset 3)
        signature = self.raw_boot[3:11]
        if signature != b'EXFAT   ':
            raise ValueError(f"Firma exFAT invalida: {signature}")

        # Desempaquetar parametros segun spec de Microsoft
        # Exponentes de tamaño (bytes por sector y sectores por cluster)
        bytes_per_sector_shift = self.raw_boot[108]
        sectors_per_cluster_shift = self.raw_boot[109]
        
        # Validar shift de seguridad
        if bytes_per_sector_shift < 9 or bytes_per_sector_shift > 12:
            raise ValueError(f"BytesPerSectorShift invalido: {bytes_per_sector_shift}")
            
        self.bytes_per_sector = 1 << bytes_per_sector_shift
        self.sectors_per_cluster = 1 << sectors_per_cluster_shift
        
        # Offsets y longitudes en sectores
        self.fat_offset = struct.unpack('<I', self.raw_boot[80:84])[0]
        self.fat_length = struct.unpack('<I', self.raw_boot[84:88])[0]
        self.cluster_heap_offset = struct.unpack('<I', self.raw_boot[88:92])[0]
        self.cluster_count = struct.unpack('<I', self.raw_boot[92:96])[0]
        self.root_directory_cluster = struct.unpack('<I', self.raw_boot[96:100])[0]
        self.volume_flags = struct.unpack('<H', self.raw_boot[106:108])[0]


class exFATDirectoryEntry:
    """Representa una entrada de directorio unificada en exFAT."""
    def __init__(self):
        self.name = ""
        self.size = 0
        self.start_cluster = 0
        self.is_directory = False
        self.is_deleted = False
        self.no_fat_chain = False
        self.created = "N/A"
        self.modified = "N/A"
        self.accessed = "N/A"
        self.attributes = 0


class exFATParser:
    """
    Analizador principal para sistemas de archivos exFAT.
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.boot_sector = exFATBootSectorParser(data_source, partition)

    def get_info(self) -> dict:
        info = {
            "Sistema de Archivos": "exFAT",
            "Bytes por sector": self.boot_sector.bytes_per_sector,
            "Sectores por clúster": self.boot_sector.sectors_per_cluster,
            "LBA Inicio FAT": self.boot_sector.fat_offset,
            "Sectores FAT": self.boot_sector.fat_length,
            "LBA Región Heap de Clústeres": self.boot_sector.cluster_heap_offset,
            "Total Clústeres": self.boot_sector.cluster_count,
            "Clúster Directorio Raíz": self.boot_sector.root_directory_cluster,
        }
        
        fat_start = self.partition.start_offset + (self.boot_sector.fat_offset * self.boot_sector.bytes_per_sector)
        info["Inicio FAT 1 (Offset absoluto)"] = f"{hex(fat_start)} (Sector/LBA: {fat_start // 512})"
        
        heap_start = self.partition.start_offset + (self.boot_sector.cluster_heap_offset * self.boot_sector.bytes_per_sector)
        info["Inicio Región de Datos (Heap)"] = f"{hex(heap_start)} (Sector/LBA: {heap_start // 512})"
        
        return info

    def get_cluster_size(self) -> int:
        return self.boot_sector.sectors_per_cluster * self.boot_sector.bytes_per_sector

    def get_cluster_offset(self, cluster_num: int) -> int:
        """Retorna el offset absoluto de un clúster dentro de la región Heap en exFAT."""
        if cluster_num < 2:
            raise ValueError("Los clústeres válidos de datos en exFAT empiezan a partir de 2.")
        
        offset_in_sectors = self.boot_sector.cluster_heap_offset + ((cluster_num - 2) * self.boot_sector.sectors_per_cluster)
        return self.partition.start_offset + (offset_in_sectors * self.boot_sector.bytes_per_sector)

    def get_fat_chain(self, start_cluster: int, no_fat_chain: bool = False, size: int = 0) -> list:
        """
        Resuelve la cadena de clústeres para un archivo/directorio exFAT.
        Si 'no_fat_chain' es True (común en exFAT), calcula la cadena secuencial directa
        sin consultar la FAT en disco.
        """
        if start_cluster < 2:
            return []

        # 1. Si el archivo es contiguo (Optimización exFAT NoFatChain)
        if no_fat_chain:
            cluster_size = self.get_cluster_size()
            num_clusters = (size + cluster_size - 1) // cluster_size if size > 0 else 1
            return [start_cluster + i for i in range(num_clusters)]

        # 2. Si no es contiguo, leer cadena de la FAT tradicional
        chain = []
        current_cluster = start_cluster
        fat_start = self.partition.start_offset + (self.boot_sector.fat_offset * self.boot_sector.bytes_per_sector)
        max_clusters = self.boot_sector.cluster_count

        while current_cluster >= 2 and len(chain) < max_clusters:
            chain.append(current_cluster)
            
            # En exFAT, cada entrada de la FAT ocupa 4 bytes (32 bits)
            entry_offset = fat_start + (current_cluster * 4)
            entry_data = self.data_source.read(entry_offset, 4)
            if not entry_data or len(entry_data) < 4:
                break
                
            next_cluster = struct.unpack('<I', entry_data)[0]
            if next_cluster >= 0xFFFFFFF8: # EOF en exFAT
                break
            if next_cluster == 0xFFFFFFF7: # Bad cluster
                break
            if next_cluster == 0:
                break
                
            current_cluster = next_cluster
            
        return chain

    def get_directory_entries(self, start_cluster: int, no_fat_chain: bool = False, size: int = 0) -> list:
        """
        Lee y parsea las entradas de un directorio exFAT.
        Agrupa los sets de registros (File + Stream + Name) en entradas unificadas.
        """
        entries = []
        chain = self.get_fat_chain(start_cluster, no_fat_chain, size)
        
        # Leer todos los clústeres del directorio a memoria
        dir_data = bytearray()
        for cluster in chain:
            offset = self.get_cluster_offset(cluster)
            dir_data.extend(self.data_source.read(offset, self.get_cluster_size()))

        idx = 0
        total_len = len(dir_data)
        
        current_entry = None
        names_collected = 0
        expected_names = 0
        
        while idx < total_len:
            entry_bytes = dir_data[idx : idx + 32]
            if len(entry_bytes) < 32:
                break
                
            first_byte = entry_bytes[0]
            
            if first_byte == 0x00:
                # Fin de directorio
                break
                
            is_deleted = (first_byte & 0x80) == 0 # En exFAT, el bit 7 a 0 indica entrada inactiva/borrada
            entry_type = first_byte & 0xFF
            
            # 1. Registro FILE (0x85 o 0x05 si está borrado)
            if entry_type in (0x85, 0x05):
                # Si había una entrada previa incompleta, la salvamos
                if current_entry and current_entry.name:
                    entries.append(current_entry)
                    
                current_entry = exFATDirectoryEntry()
                current_entry.is_deleted = is_deleted
                
                # Atributos de archivo
                current_entry.attributes = struct.unpack('<I', entry_bytes[4:8])[0]
                current_entry.is_directory = (current_entry.attributes & 0x10) != 0
                
                # Timestamps
                try:
                    c_time = struct.unpack('<I', entry_bytes[8:12])[0]
                    m_time = struct.unpack('<I', entry_bytes[12:16])[0]
                    a_time = struct.unpack('<I', entry_bytes[16:20])[0]
                    current_entry.created = parse_dos_time(c_time & 0xFFFF, (c_time >> 16) & 0xFFFF)
                    current_entry.modified = parse_dos_time(m_time & 0xFFFF, (m_time >> 16) & 0xFFFF)
                    current_entry.accessed = parse_dos_time(a_time & 0xFFFF, (a_time >> 16) & 0xFFFF)
                except Exception:
                    pass
                
                # Cantidad de entradas secundarias en el set (Stream Extension + Names)
                secondary_count = entry_bytes[1]
                expected_names = secondary_count - 1 # Restando el Stream Extension
                names_collected = 0
                
            # 2. Registro STREAM EXTENSION (0xC0 o 0x40 si está borrado)
            elif entry_type in (0xC0, 0x40) and current_entry:
                general_flags = entry_bytes[1]
                # Bit 0: Allocated, Bit 1: NoFatChain
                current_entry.no_fat_chain = (general_flags & 0x02) != 0
                
                # Offset 20: First cluster (4 bytes)
                current_entry.start_cluster = struct.unpack('<I', entry_bytes[20:24])[0]
                # Offset 24: Data length (8 bytes)
                current_entry.size = struct.unpack('<Q', entry_bytes[24:32])[0]
                
            # 3. Registro FILE NAME (0xC1 o 0x41 si está borrado)
            elif entry_type in (0xC1, 0x41) and current_entry:
                # El nombre UTF-16LE empieza en el offset 2 y ocupa hasta 30 bytes
                name_chunk_bytes = entry_bytes[2:32]
                try:
                    name_chunk = name_chunk_bytes.decode('utf-16le').split('\x00')[0]
                    current_entry.name += name_chunk
                except Exception:
                    pass
                    
                names_collected += 1
                # Si recolectamos todos los nombres esperados, salvamos la entrada
                if names_collected >= expected_names:
                    if current_entry.name:
                        entries.append(current_entry)
                    current_entry = None
            
            # Avanzar a la siguiente entrada de 32 bytes
            idx += 32
            
        # Salvar entrada residual si existe
        if current_entry and current_entry.name:
            entries.append(current_entry)
            
        return entries
