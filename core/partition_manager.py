import struct
import uuid
from dataclasses import dataclass
from core.data_source import DataSource
from core.i18n import _

@dataclass
class Partition:
    bootable: bool
    type_code: int
    type_name: str
    start_lba: int
    size_in_sectors: int
    sector_size: int = 512
    raw_bytes: bytes = b""

    @property
    def start_offset(self) -> int:
        return self.start_lba * self.sector_size
    
    @property
    def size_in_bytes(self) -> int:
        return self.size_in_sectors * self.sector_size

class MBRParser:
    """
    Analizador de Master Boot Record (MBR).
    Este es un gran punto de partida educativo para entender cómo
    un disco físico se divide en volúmenes lógicos.
    """
    
    PARTITION_TYPES = {
        0x07: "NTFS / exFAT",
        0x0B: "FAT32",
        0x0C: "FAT32 (LBA)",
        0x83: "Linux ext",
        0x05: "Extended Partition",
        0x0F: "Extended Partition (LBA)"
    }

    def __init__(self, data_source: DataSource, sector_size: int = 512):
        self.data_source = data_source
        self.sector_size = sector_size
        self.partitions = []
        self._parse()

    def _parse(self):
        # El MBR se encuentra en el primer sector (Sector 0)
        mbr_data = self.data_source.read(0, self.sector_size)
        
        # Validar la firma del MBR (0x55AA al final del sector)
        signature = mbr_data[510:512]
        if signature != b'\x55\xaa':
            raise ValueError(f"Firma MBR inválida: {signature.hex()}")

        # La tabla de particiones comienza en el offset 446 y contiene 4 entradas de 16 bytes
        partition_table_offset = 446
        
        for i in range(4):
            entry_offset = partition_table_offset + (i * 16)
            entry_data = mbr_data[entry_offset : entry_offset + 16]
            
            # Formato de la entrada (16 bytes):
            # Byte 0: Status (0x80 = bootable, 0x00 = non-bootable)
            # Bytes 1-3: CHS First sector (ignorado en sistemas modernos)
            # Byte 4: Partition type
            # Bytes 5-7: CHS Last sector (ignorado)
            # Bytes 8-11: LBA of first absolute sector (Little Endian)
            # Bytes 12-15: Number of sectors in partition (Little Endian)
            
            status, _chs1, p_type, _chs2, start_lba, num_sectors = struct.unpack('<B3sB3sII', entry_data)
            
            # Identificar particiones vacías vs particiones borradas
            if p_type == 0x00:
                if num_sectors == 0:
                    continue  # Entrada verdaderamente vacía
                else:
                    type_name = "BORRADA / UNALLOCATED (Tipo 0x00)"
            else:
                type_name = self.PARTITION_TYPES.get(p_type, f"Unknown (0x{p_type:02X})")
            
            bootable = (status == 0x80)
            
            partition = Partition(
                bootable=bootable,
                type_code=p_type,
                type_name=type_name,
                start_lba=start_lba,
                size_in_sectors=num_sectors,
                sector_size=self.sector_size,
                raw_bytes=entry_data
            )
            self.partitions.append(partition)
            
        # Detección de GPT (GUID Partition Table)
        if len(self.partitions) > 0 and self.partitions[0].type_code == 0xEE:
            print(_("\n[+] Detectado Protective MBR (0xEE). Saltando al LBA 1 para parsear GPT..."))
            self.partitions.clear()
            self._parse_gpt()

    def _parse_gpt(self):
        # GPT Header está en el LBA 1 (Sector 1)
        gpt_header = self.data_source.read(self.sector_size, self.sector_size)
        signature = gpt_header[0:8]
        if signature != b'EFI PART':
            print(_("Alerta: Partición MBR indica GPT (0xEE) pero la firma 'EFI PART' no se encontró en LBA 1."))
            return
            
        entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_entries = struct.unpack('<I', gpt_header[80:84])[0]
        entry_size = struct.unpack('<I', gpt_header[84:88])[0]
        
        # Leer el array de entradas de partición
        entries_data = self.data_source.read(entries_lba * self.sector_size, num_entries * entry_size)
        
        for i in range(num_entries):
            entry = entries_data[i*entry_size : (i+1)*entry_size]
            type_guid_bytes = entry[0:16]
            
            # GUID de 16 ceros significa entrada vacía
            if type_guid_bytes == b'\x00'*16:
                continue 
                
            # Parsear GUID (Windows usa bytes en Little Endian para los primeros 3 componentes)
            type_guid = uuid.UUID(bytes_le=type_guid_bytes)
            
            first_lba, last_lba = struct.unpack('<QQ', entry[32:48])
            num_sectors = (last_lba - first_lba) + 1
            
            # Mapeo básico de GUIDs comunes a "type_codes" antiguos para compatibilidad de nuestro Shell
            type_name = "GPT Partition"
            guid_str = str(type_guid).upper()
            
            if guid_str == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7":
                type_name = "Basic Data Partition (Windows)"
                type_code = 0x07 # Forzamos NTFS/FAT para el NTFSShell
            elif guid_str == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B":
                type_name = "EFI System Partition"
                type_code = 0x0B # Forzamos FAT32 para compatibilidad
            elif guid_str == "0FC63DAF-8483-4772-8E79-3D69D8477DE4":
                type_name = "Linux Filesystem Data"
                type_code = 0x83 # Ext4
            else:
                type_code = 0xFF # Desconocido/Otro
                
            # Extraer el nombre de la partición si lo tiene
            name_bytes = entry[56:128]
            try:
                part_name = name_bytes.decode('utf-16le').rstrip('\x00')
                if part_name:
                    type_name += f" [{part_name}]"
            except:
                pass
                
            partition = Partition(
                bootable=False, # GPT no usa flag bootable de la misma forma (usa UEFI)
                type_code=type_code,
                type_name=type_name,
                start_lba=first_lba,
                size_in_sectors=num_sectors,
                sector_size=self.sector_size,
                raw_bytes=entry
            )
            self.partitions.append(partition)
