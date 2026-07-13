import struct
from core.data_source import DataSource
from core.partition_manager import Partition
from datetime import datetime

class Ext4SuperblockParser:
    """
    Analizador del Superbloque de Ext4.
    El superbloque se encuentra siempre en el offset 1024 (0x400) de la partición
    y contiene la configuración maestra del sistema de archivos.
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.magic = 0
        self.inodes_count = 0
        self.blocks_count = 0
        self.free_blocks_count = 0
        self.free_inodes_count = 0
        self.first_data_block = 0
        self.log_block_size = 0
        self.blocks_per_group = 0
        self.inodes_per_group = 0
        self.mtime = 0
        self.wtime = 0
        self.volume_name = ""
        self.last_mounted = ""
        
        self._parse_superblock()
        
    def _parse_superblock(self):
        # El superbloque siempre empieza en el offset 1024 relativo al inicio de la partición
        sb_offset = self.partition.start_offset + 1024
        
        # Leemos los primeros 256 bytes del superbloque (suelen ser 1024 en total, pero los primordiales están aquí)
        self.raw_sb = self.data_source.read(sb_offset, 256)
        
        # Firma mágica en offset 0x38 (56 bytes desde el inicio del SB)
        self.magic = struct.unpack('<H', self.raw_sb[0x38:0x3A])[0]
        if self.magic != 0xEF53:
            raise ValueError(f"No es una partición Ext2/3/4 válida. Firma mágica encontrada: {hex(self.magic)}")
            
        self.inodes_count = struct.unpack('<I', self.raw_sb[0x00:0x04])[0]
        self.blocks_count = struct.unpack('<I', self.raw_sb[0x04:0x08])[0]
        self.free_blocks_count = struct.unpack('<I', self.raw_sb[0x0C:0x10])[0]
        self.free_inodes_count = struct.unpack('<I', self.raw_sb[0x10:0x14])[0]
        self.first_data_block = struct.unpack('<I', self.raw_sb[0x14:0x18])[0]
        
        self.log_block_size = struct.unpack('<I', self.raw_sb[0x18:0x1C])[0]
        self.block_size = 1024 * (2 ** self.log_block_size)
        
        self.blocks_per_group = struct.unpack('<I', self.raw_sb[0x20:0x24])[0]
        self.inodes_per_group = struct.unpack('<I', self.raw_sb[0x28:0x2C])[0]
        
        self.mtime = struct.unpack('<I', self.raw_sb[0x2C:0x30])[0]
        self.wtime = struct.unpack('<I', self.raw_sb[0x30:0x34])[0]
        
        # Nombres (si están definidos, offset 120 para volumen)
        try:
            self.volume_name = self.raw_sb[120:136].decode('utf-8').rstrip('\x00')
        except:
            self.volume_name = "<Desconocido>"
            
        try:
            self.last_mounted = self.raw_sb[136:200].decode('utf-8').rstrip('\x00')
        except:
            self.last_mounted = "<Desconocido>"
            
        # Tamaño del inodo
        self.inode_size = struct.unpack('<H', self.raw_sb[0x58:0x5A])[0]
        
        # 64-bit features
        incompat_features = struct.unpack('<I', self.raw_sb[0x60:0x64])[0]
        self.is_64bit = (incompat_features & 0x80) != 0
        
        if self.is_64bit and len(self.raw_sb) >= 256:
            self.desc_size = struct.unpack('<H', self.raw_sb[0xFE:0x100])[0]
        else:
            self.desc_size = 32

    def format_time(self, timestamp: int) -> str:
        if timestamp == 0:
            return "N/A"
        try:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "Fecha Inválida"

class Ext4Parser:
    """
    Clase principal para analizar un sistema de archivos Ext4.
    Por ahora se centra en el Superbloque (nivel educativo inicial).
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.superblock = Ext4SuperblockParser(data_source, partition)

    def get_group_descriptor(self, group_num: int) -> int:
        """Obtiene el bloque físico donde comienza la Tabla de Inodos para un Grupo de Bloques."""
        # La tabla GDT comienza en el bloque que sigue al bloque que contiene al superbloque
        gdt_block = self.superblock.first_data_block + 1
        offset = self.partition.start_offset + (gdt_block * self.superblock.block_size) + (group_num * self.superblock.desc_size)
        raw_desc = self.data_source.read(offset, self.superblock.desc_size)
        
        bg_inode_table_lo = struct.unpack('<I', raw_desc[8:12])[0]
        if self.superblock.is_64bit and self.superblock.desc_size >= 64:
            bg_inode_table_hi = struct.unpack('<I', raw_desc[40:44])[0]
        else:
            bg_inode_table_hi = 0
            
        return (bg_inode_table_hi << 32) | bg_inode_table_lo

    def get_inode(self, inode_num: int) -> bytes:
        """Lee el contenido binario de un Inodo."""
        # Los inodos empiezan a contar en 1
        group_num = (inode_num - 1) // self.superblock.inodes_per_group
        index_in_group = (inode_num - 1) % self.superblock.inodes_per_group
        
        inode_table_block = self.get_group_descriptor(group_num)
        offset = self.partition.start_offset + (inode_table_block * self.superblock.block_size) + (index_in_group * self.superblock.inode_size)
        return self.data_source.read(offset, self.superblock.inode_size)

    def get_inode_data_blocks(self, inode_data: bytes) -> list:
        """Parse el árbol de Extents de Ext4 para obtener los bloques físicos de datos de un Inodo."""
        # Array i_block (60 bytes) en el offset 40 del Inodo
        i_block = inode_data[40:100]
        magic = struct.unpack('<H', i_block[0:2])[0]
        blocks = []
        
        if magic == 0xF30A: # Magic de Extents
            entries = struct.unpack('<H', i_block[2:4])[0]
            depth = struct.unpack('<H', i_block[6:8])[0]
            
            if depth == 0: # Nodo Hoja (Apunta a bloques de datos directamente)
                for i in range(entries):
                    ext_offset = 12 + (i * 12)
                    ee_len = struct.unpack('<H', i_block[ext_offset+4:ext_offset+6])[0]
                    ee_start_hi = struct.unpack('<H', i_block[ext_offset+6:ext_offset+8])[0]
                    ee_start_lo = struct.unpack('<I', i_block[ext_offset+8:ext_offset+12])[0]
                    physical_block = (ee_start_hi << 32) | ee_start_lo
                    for b in range(ee_len):
                        blocks.append(physical_block + b)
            # Para profundidad > 0, se requeriría leer bloques índice recursivamente.
            # Por ahora soportamos directorios/archivos moderados.
            
        return blocks

    def get_directory_entries(self, inode_num: int) -> list:
        """Lista los archivos contenidos dentro de un directorio leyendo su inodo."""
        inode_data = self.get_inode(inode_num)
        
        # Verificar si es un directorio (i_mode en offset 0)
        i_mode = struct.unpack('<H', inode_data[0:2])[0]
        if not (i_mode & 0x4000):
            raise ValueError(f"El Inodo {inode_num} no es un directorio.")
            
        blocks = self.get_inode_data_blocks(inode_data)
        entries = []
        
        for b in blocks:
            offset = self.partition.start_offset + (b * self.superblock.block_size)
            dir_data = self.data_source.read(offset, self.superblock.block_size)
            
            idx = 0
            while idx < len(dir_data):
                inode = struct.unpack('<I', dir_data[idx:idx+4])[0]
                if inode == 0:
                    break # Falso positivo o final de entradas válidas
                    
                rec_len = struct.unpack('<H', dir_data[idx+4:idx+6])[0]
                if rec_len == 0:
                    break
                    
                name_len = dir_data[idx+6]
                file_type = dir_data[idx+7]
                name = dir_data[idx+8 : idx+8+name_len].decode('ascii', errors='ignore')
                
                # file_type: 1 = Archivo, 2 = Directorio
                entries.append({
                    "inode": inode,
                    "name": name,
                    "type": "DIR" if file_type == 2 else "FILE"
                })
                idx += rec_len
                
        return entries

    def read_file(self, inode_num: int) -> bytes:
        """Lee el contenido binario de un archivo a partir de su Inodo."""
        inode_data = self.get_inode(inode_num)
        
        # Validar tipo de archivo
        i_mode = struct.unpack('<H', inode_data[0:2])[0]
        if i_mode & 0x4000:
            raise ValueError(f"El Inodo {inode_num} es un directorio, no un archivo regular.")
            
        # Tamaño del archivo (32-bit bajo)
        size_lo = struct.unpack('<I', inode_data[4:8])[0]
        
        blocks = self.get_inode_data_blocks(inode_data)
        data_buffer = bytearray()
        
        for b in blocks:
            offset = self.partition.start_offset + (b * self.superblock.block_size)
            data_buffer.extend(self.data_source.read(offset, self.superblock.block_size))
            
        return bytes(data_buffer[:size_lo])
