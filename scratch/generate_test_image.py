import struct
import uuid
import binascii

def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xffffffff

def create_protective_mbr(total_sectors: int) -> bytes:
    mbr = bytearray(512)
    # Primera particion (offset 446)
    struct.pack_into('<B', mbr, 446, 0x00)
    struct.pack_into('<3B', mbr, 447, 0x00, 0x02, 0x00)
    struct.pack_into('<B', mbr, 450, 0xEE)
    struct.pack_into('<3B', mbr, 451, 0xFF, 0xFF, 0xFF)
    struct.pack_into('<I', mbr, 454, 1)
    struct.pack_into('<I', mbr, 458, total_sectors - 1)
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr)

def create_gpt_structures(total_sectors: int) -> tuple[bytes, bytes]:
    gpt_header = bytearray(512)
    struct.pack_into('<8s', gpt_header, 0, b'EFI PART')
    struct.pack_into('<I', gpt_header, 8, 0x00010000) # Revision
    struct.pack_into('<I', gpt_header, 12, 92) # Size
    struct.pack_into('<Q', gpt_header, 24, 1)
    struct.pack_into('<Q', gpt_header, 32, total_sectors - 1)
    struct.pack_into('<Q', gpt_header, 40, 34)
    struct.pack_into('<Q', gpt_header, 48, total_sectors - 34)
    
    disk_guid = uuid.uuid4().bytes
    gpt_header[56:72] = disk_guid
    
    struct.pack_into('<Q', gpt_header, 72, 2)
    struct.pack_into('<I', gpt_header, 80, 128)
    struct.pack_into('<I', gpt_header, 84, 128)
    
    entries = bytearray(128 * 128)
    
    part_types = [
        # Particion 1: FAT12
        ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", 2048, 4095, "FAT12_MOCK"), # 2048 sectores
        # Particion 2: FAT16
        ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", 4096, 14335, "FAT16_MOCK"), # 10240 sectores
        # Particion 3: FAT32
        ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", 14336, 89999, "FAT32_MOCK"), # 75664 sectores
        # Particion 4: exFAT
        ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", 90000, 92047, "exFAT_MOCK"), # 2048 sectores
        # Particion 5: NTFS
        ("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", 92048, 94095, "NTFS_MOCK"), # 2048 sectores
        # Particion 6: Ext4
        ("0FC63DAF-8483-4772-8E79-3D69D8477DE4", 94096, 96143, "Ext4_MOCK") # 2048 sectores
    ]
    
    for idx, (type_guid_str, start, end, name) in enumerate(part_types):
        entry_offset = idx * 128
        type_guid = uuid.UUID(type_guid_str).bytes_le
        part_guid = uuid.uuid4().bytes_le
        
        entries[entry_offset : entry_offset + 16] = type_guid
        entries[entry_offset + 16 : entry_offset + 32] = part_guid
        
        struct.pack_into('<Q', entries, entry_offset + 32, start)
        struct.pack_into('<Q', entries, entry_offset + 40, end)
        struct.pack_into('<Q', entries, entry_offset + 48, 0)
        
        name_utf16 = name.encode('utf-16le')
        entries[entry_offset + 56 : entry_offset + 56 + len(name_utf16)] = name_utf16
        
    entries_crc = crc32(entries)
    struct.pack_into('<I', gpt_header, 88, entries_crc)
    
    struct.pack_into('<I', gpt_header, 16, 0)
    header_crc = crc32(gpt_header[:92])
    struct.pack_into('<I', gpt_header, 16, header_crc)
    
    return bytes(gpt_header), bytes(entries)


# --- FORMATADORES DE SISTEMAS DE ARCHIVOS ---

def format_fat12_partition() -> bytes:
    part = bytearray(2048 * 512)
    
    struct.pack_into('<3s', part, 0, b'\xeb\x3c\x90')
    struct.pack_into('<8s', part, 3, b'MSDOS5.0')
    struct.pack_into('<H', part, 11, 512) # Bytes per sector
    struct.pack_into('<B', part, 13, 2) # Sectors per cluster
    struct.pack_into('<H', part, 14, 1) # Reserved sectors
    struct.pack_into('<B', part, 16, 1) # Num FATs
    struct.pack_into('<H', part, 17, 64) # Root entries count
    struct.pack_into('<H', part, 19, 2048) # Total sectors
    struct.pack_into('<B', part, 21, 0xF8)
    struct.pack_into('<H', part, 22, 6) # Sectors per FAT
    
    struct.pack_into('<B', part, 38, 0x29)
    struct.pack_into('<I', part, 39, 0x12345678)
    struct.pack_into('<11s', part, 43, b'FAT12_MOCK ')
    struct.pack_into('<8s', part, 54, b'FAT12   ')
    part[510:512] = b'\x55\xaa'
    
    fat_offset = 1 * 512
    part[fat_offset + 0] = 0xF9
    part[fat_offset + 1] = 0xFF
    part[fat_offset + 2] = 0xFF
    part[fat_offset + 3] = 0xFF
    part[fat_offset + 4] = 0xFF
    part[fat_offset + 5] = 0xFF
    
    root_offset = 7 * 512
    struct.pack_into('<8s3s', part, root_offset, b'HELLO   ', b'TXT')
    struct.pack_into('<B', part, root_offset + 11, 0x20)
    struct.pack_into('<HH', part, root_offset + 22, 0x54C0, 0x5CD6)
    struct.pack_into('<H', part, root_offset + 26, 2)
    struct.pack_into('<I', part, root_offset + 28, 16)
    
    struct.pack_into('<B7s3s', part, root_offset + 32, 0xE5, b'ELETED ', b'TXT')
    struct.pack_into('<B', part, root_offset + 32 + 11, 0x20)
    struct.pack_into('<HH', part, root_offset + 32 + 22, 0x54C0, 0x5CD6)
    struct.pack_into('<H', part, root_offset + 32 + 26, 3)
    struct.pack_into('<I', part, root_offset + 32 + 28, 24)
    
    c2_offset = 11 * 512
    part[c2_offset : c2_offset + 16] = b'HELLO FAT12 DATA'
    
    c3_offset = 13 * 512
    part[c3_offset : c3_offset + 24] = b'DELETED FAT12 MOCK DATA!'
    
    return bytes(part)


def format_fat16_partition() -> bytes:
    # 10240 sectores
    part = bytearray(10240 * 512)
    
    struct.pack_into('<3s', part, 0, b'\xeb\x3c\x90')
    struct.pack_into('<8s', part, 3, b'MSDOS5.0')
    struct.pack_into('<H', part, 11, 512)
    struct.pack_into('<B', part, 13, 1) # 1 sector per cluster to maximize cluster count -> ~10200 clusters (FAT16)
    struct.pack_into('<H', part, 14, 1)
    struct.pack_into('<B', part, 16, 1)
    struct.pack_into('<H', part, 17, 64)
    struct.pack_into('<H', part, 19, 10240)
    struct.pack_into('<B', part, 21, 0xF8)
    struct.pack_into('<H', part, 22, 40) # 40 sectores por FAT
    
    struct.pack_into('<B', part, 38, 0x29)
    struct.pack_into('<I', part, 39, 0x87654321)
    struct.pack_into('<11s', part, 43, b'FAT16_MOCK ')
    struct.pack_into('<8s', part, 54, b'FAT16   ')
    part[510:512] = b'\x55\xaa'
    
    fat_offset = 1 * 512
    struct.pack_into('<HH', part, fat_offset, 0xFFF8, 0xFFFF)
    struct.pack_into('<HH', part, fat_offset + 4, 0xFFFF, 0xFFFF)
    
    # Root dir LBA: 1 reserved + 1 * 40 FAT = 41
    root_offset = 41 * 512
    struct.pack_into('<8s3s', part, root_offset, b'HELLO   ', b'TXT')
    struct.pack_into('<B', part, root_offset + 11, 0x20)
    struct.pack_into('<HH', part, root_offset + 22, 0x54C0, 0x5CD6)
    struct.pack_into('<H', part, root_offset + 26, 2)
    struct.pack_into('<I', part, root_offset + 28, 16)
    
    struct.pack_into('<B7s3s', part, root_offset + 32, 0xE5, b'ELETED ', b'TXT')
    struct.pack_into('<B', part, root_offset + 32 + 11, 0x20)
    struct.pack_into('<HH', part, root_offset + 32 + 22, 0x54C0, 0x5CD6)
    struct.pack_into('<H', part, root_offset + 32 + 26, 3)
    struct.pack_into('<I', part, root_offset + 32 + 28, 24)
    
    # Data LBA starts at: 41 + 4 (root dir sectors) = 45
    # Cluster 2 = LBA 45
    c2_offset = 45 * 512
    part[c2_offset : c2_offset + 16] = b'HELLO FAT16 DATA'
    
    # Cluster 3 = LBA 46
    c3_offset = 46 * 512
    part[c3_offset : c3_offset + 24] = b'DELETED FAT16 MOCK DATA!'
    
    return bytes(part)


def format_fat32_partition() -> bytes:
    # 75664 sectores
    part = bytearray(75664 * 512)
    
    struct.pack_into('<3s', part, 0, b'\xeb\x58\x90')
    struct.pack_into('<8s', part, 3, b'MSDOS5.0')
    struct.pack_into('<H', part, 11, 512)
    struct.pack_into('<B', part, 13, 1) # 1 sector per cluster -> ~75000 clusters (FAT32)
    struct.pack_into('<H', part, 14, 32)
    struct.pack_into('<B', part, 16, 1)
    struct.pack_into('<H', part, 17, 0)
    struct.pack_into('<H', part, 19, 0)
    struct.pack_into('<I', part, 32, 75664)
    struct.pack_into('<I', part, 36, 300) # 300 sectores por FAT
    struct.pack_into('<H', part, 40, 0)
    struct.pack_into('<H', part, 42, 0)
    struct.pack_into('<I', part, 44, 2) # Root cluster
    struct.pack_into('<11s', part, 71, b'FAT32_MOCK ')
    struct.pack_into('<8s', part, 82, b'FAT32   ')
    part[510:512] = b'\x55\xaa'
    
    fat_offset = 32 * 512
    struct.pack_into('<II', part, fat_offset, 0x0FFFFFF8, 0x0FFFFFFF)
    struct.pack_into('<I', part, fat_offset + 8, 0x0FFFFFFF)
    struct.pack_into('<I', part, fat_offset + 12, 0x0FFFFFFF)
    struct.pack_into('<I', part, fat_offset + 16, 0x0FFFFFFF)
    
    # Data LBA starts at: 32 + 300 = 332
    # Cluster 2 (Root Dir) = LBA 332
    c2_offset = 332 * 512
    struct.pack_into('<8s3s', part, c2_offset, b'NOTES   ', b'TXT')
    struct.pack_into('<B', part, c2_offset + 11, 0x20)
    struct.pack_into('<H', part, c2_offset + 26, 3)
    struct.pack_into('<I', part, c2_offset + 28, 16)
    
    struct.pack_into('<B7s3s', part, c2_offset + 32, 0xE5, b'ELETED ', b'TXT')
    struct.pack_into('<B', part, c2_offset + 32 + 11, 0x20)
    struct.pack_into('<H', part, c2_offset + 32 + 26, 4)
    struct.pack_into('<I', part, c2_offset + 32 + 28, 24)
    
    # Cluster 3 = LBA 333
    c3_offset = 333 * 512
    part[c3_offset : c3_offset + 16] = b'HELLO FAT32 DATA'
    
    # Cluster 4 = LBA 334
    c4_offset = 334 * 512
    part[c4_offset : c4_offset + 24] = b'DELETED FAT32 MOCK DATA!'
    
    # Cluster 5 = LBA 335 (Sembramos firma JPEG para testing de Carving)
    c5_offset = 335 * 512
    part[c5_offset : c5_offset + 10] = b'\xFF\xD8\xFF_JPEG_\xFF\xD9'
    
    return bytes(part)


def format_exfat_partition() -> bytes:
    part = bytearray(2048 * 512)
    
    struct.pack_into('<3s', part, 0, b'\xeb\x76\x90')
    struct.pack_into('<8s', part, 3, b'EXFAT   ')
    part[108] = 9
    part[109] = 1
    part[110] = 1
    
    struct.pack_into('<I', part, 80, 64)
    struct.pack_into('<I', part, 84, 8)
    struct.pack_into('<I', part, 88, 128)
    struct.pack_into('<I', part, 92, 900)
    struct.pack_into('<I', part, 96, 2)
    part[510:512] = b'\x55\xaa'
    
    for i in range(12):
        part[i*512 + 510 : i*512 + 512] = b'\x55\xaa'
        
    fat_offset = 64 * 512
    struct.pack_into('<III', part, fat_offset, 0xFFFFFFF8, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into('<II', part, fat_offset + 12, 0xFFFFFFFF, 0xFFFFFFFF)
    
    c2_offset = 128 * 512
    
    # exfat.dat
    part[c2_offset + 0] = 0x85
    part[c2_offset + 1] = 2
    struct.pack_into('<I', part, c2_offset + 4, 0x20)
    part[c2_offset + 32] = 0xC0
    part[c2_offset + 33] = 0x03
    struct.pack_into('<I', part, c2_offset + 32 + 20, 3)
    struct.pack_into('<Q', part, c2_offset + 32 + 24, 16)
    part[c2_offset + 64] = 0xC1
    name1 = "exfat.dat".encode('utf-16le')
    part[c2_offset + 64 + 2 : c2_offset + 64 + 2 + len(name1)] = name1
    
    # deleted.dat
    part[c2_offset + 96] = 0x05
    part[c2_offset + 97] = 2
    struct.pack_into('<I', part, c2_offset + 96 + 4, 0x20)
    part[c2_offset + 128] = 0x40
    part[c2_offset + 129] = 0x03
    struct.pack_into('<I', part, c2_offset + 128 + 20, 4)
    struct.pack_into('<Q', part, c2_offset + 128 + 24, 24)
    part[c2_offset + 160] = 0x41
    name2 = "deleted.dat".encode('utf-16le')
    part[c2_offset + 160 + 2 : c2_offset + 160 + 2 + len(name2)] = name2
    
    c3_offset = 130 * 512
    part[c3_offset : c3_offset + 16] = b'HELLO EXFAT DATA'
    
    c4_offset = 132 * 512
    part[c4_offset : c4_offset + 24] = b'DELETED EXFAT MOCK DATA!'
    
    return bytes(part)


def create_ntfs_mft_record(record_id: int, parent_id: int, name: str, data: bytes, active: bool = True) -> bytes:
    rec = bytearray(1024)
    struct.pack_into('<4s', rec, 0, b'FILE')
    struct.pack_into('<H', rec, 4, 9)
    struct.pack_into('<H', rec, 6, 1)
    struct.pack_into('<Q', rec, 8, 1)
    struct.pack_into('<H', rec, 16, 1)
    struct.pack_into('<H', rec, 18, 1)
    struct.pack_into('<H', rec, 20, 56)
    struct.pack_into('<H', rec, 22, 1 if active else 0)
    struct.pack_into('<I', rec, 24, 400)
    struct.pack_into('<I', rec, 28, 1024)
    struct.pack_into('<Q', rec, 32, 0)
    struct.pack_into('<H', rec, 44, record_id)
    
    attr_SI = 56
    struct.pack_into('<I', rec, attr_SI, 0x10)
    struct.pack_into('<I', rec, attr_SI + 4, 72)
    rec[attr_SI + 8] = 0
    rec[attr_SI + 9] = 0
    struct.pack_into('<H', rec, attr_SI + 20, 24) # Content offset = 24 (at offset 20)
    struct.pack_into('<I', rec, attr_SI + 16, 48) # Content size
    struct.pack_into('<Q', rec, attr_SI + 24, 0x01D9D9C96726D000)
    struct.pack_into('<Q', rec, attr_SI + 32, 0x01D9D9C96726D000)
    
    attr_FN = 128
    name_len = len(name)
    content_size = 66 + name_len * 2
    total_size = (content_size + 24 + 7) & ~7
    
    struct.pack_into('<I', rec, attr_FN, 0x30)
    struct.pack_into('<I', rec, attr_FN + 4, total_size)
    rec[attr_FN + 8] = 0
    struct.pack_into('<H', rec, attr_FN + 20, 24) # Content offset = 24 (at offset 20)
    struct.pack_into('<I', rec, attr_FN + 16, content_size) # Content size
    
    fn_content = attr_FN + 24
    struct.pack_into('<Q', rec, fn_content, parent_id)
    struct.pack_into('<Q', rec, fn_content + 8, 0x01D9D9C96726D000)
    struct.pack_into('<Q', rec, fn_content + 16, 0x01D9D9C96726D000)
    struct.pack_into('<QQ', rec, fn_content + 40, len(data), len(data))
    rec[fn_content + 64] = name_len
    rec[fn_content + 65] = 0x01
    name_utf16 = name.encode('utf-16le')
    rec[fn_content + 66 : fn_content + 66 + len(name_utf16)] = name_utf16
    
    attr_DATA = attr_FN + total_size
    data_content_size = len(data)
    data_total_size = (data_content_size + 24 + 7) & ~7
    
    struct.pack_into('<I', rec, attr_DATA, 0x80)
    struct.pack_into('<I', rec, attr_DATA + 4, data_total_size)
    rec[attr_DATA + 8] = 0
    struct.pack_into('<H', rec, attr_DATA + 20, 24) # Content offset = 24 (at offset 20)
    struct.pack_into('<I', rec, attr_DATA + 16, data_content_size)
    rec[attr_DATA + 24 : attr_DATA + 24 + data_content_size] = data
    
    end_offset = attr_DATA + data_total_size
    struct.pack_into('<I', rec, end_offset, 0xFFFFFFFF)
    
    return bytes(rec)


def format_ntfs_partition() -> bytes:
    part = bytearray(2048 * 512)
    
    struct.pack_into('<3s', part, 0, b'\xeb\x52\x90')
    struct.pack_into('<8s', part, 3, b'NTFS    ')
    struct.pack_into('<H', part, 11, 512)
    struct.pack_into('<B', part, 13, 2)
    struct.pack_into('<b', part, 64, -10) # Bytes per MFT record = 2^|-10| = 1024 bytes
    struct.pack_into('<Q', part, 48, 4)
    part[510:512] = b'\x55\xaa'
    
    mft_offset = 8 * 512
    r0 = create_ntfs_mft_record(0, 5, "$MFT", b"", active=True)
    part[mft_offset : mft_offset + 1024] = r0
    
    r5 = create_ntfs_mft_record(5, 5, ".", b"", active=True)
    r5_mut = bytearray(r5)
    struct.pack_into('<H', r5_mut, 22, 3)
    part[mft_offset + 5*1024 : mft_offset + 5*1024 + 1024] = r5_mut
    
    r30 = create_ntfs_mft_record(30, 5, "hello.txt", b"HELLO NTFS DATA", active=True)
    part[mft_offset + 30*1024 : mft_offset + 30*1024 + 1024] = r30
    
    r31 = create_ntfs_mft_record(31, 5, "deleted.txt", b"DELETED NTFS MOCK DATA!", active=False)
    part[mft_offset + 31*1024 : mft_offset + 31*1024 + 1024] = r31
    
    return bytes(part)


def format_ext4_partition() -> bytes:
    part = bytearray(2048 * 512)
    
    sb_offset = 1024
    struct.pack_into('<H', part, sb_offset + 56, 0xEF53) # Magic (0x38 = 56)
    struct.pack_into('<I', part, sb_offset + 20, 1)      # s_first_data_block = 1 (0x14 = 20)
    struct.pack_into('<I', part, sb_offset + 24, 0)      # s_log_block_size (0x18 = 24)
    struct.pack_into('<I', part, sb_offset + 32, 8192)   # s_blocks_per_group (0x20 = 32)
    struct.pack_into('<I', part, sb_offset + 40, 2048)   # s_inodes_per_group (0x28 = 40)
    struct.pack_into('<I', part, sb_offset + 4, 2048)    # s_blocks_count (0x04)
    struct.pack_into('<H', part, sb_offset + 88, 256)     # s_inode_size = 256 (0x58 = 88)
    
    gd_offset = 2048
    struct.pack_into('<I', part, gd_offset + 8, 5)
    
    inode_table_offset = 5120
    root_inode_offset = inode_table_offset + 256
    
    struct.pack_into('<H', part, root_inode_offset, 0x41ED)
    struct.pack_into('<I', part, root_inode_offset + 4, 1024)
    struct.pack_into('<H', part, root_inode_offset + 26, 2)
    # Extents en i_block (offset 40) para inodo 2 (directorio raiz) -> bloque fisico 10
    struct.pack_into('<HHHHI', part, root_inode_offset + 40, 0xF30A, 1, 4, 0, 0)
    struct.pack_into('<IHHI', part, root_inode_offset + 52, 0, 1, 0, 10)
    
    dir_block_offset = 10240
    struct.pack_into('<I', part, dir_block_offset, 2)
    struct.pack_into('<H', part, dir_block_offset + 4, 12)
    part[dir_block_offset + 6] = 1
    part[dir_block_offset + 7] = 2
    part[dir_block_offset + 8 : dir_block_offset + 9] = b'.'
    
    struct.pack_into('<I', part, dir_block_offset + 12, 2)
    struct.pack_into('<H', part, dir_block_offset + 12 + 4, 12)
    part[dir_block_offset + 12 + 6] = 2
    part[dir_block_offset + 12 + 7] = 2
    part[dir_block_offset + 12 + 8 : dir_block_offset + 10] = b'..'
    
    struct.pack_into('<I', part, dir_block_offset + 24, 12)
    struct.pack_into('<H', part, dir_block_offset + 24 + 4, 1000)
    part[dir_block_offset + 24 + 6] = 9
    part[dir_block_offset + 24 + 7] = 1
    part[dir_block_offset + 24 + 8 : dir_block_offset + 33] = b'hello.txt'
    
    file_inode_offset = inode_table_offset + 11 * 256
    struct.pack_into('<H', part, file_inode_offset, 0x81A4)
    struct.pack_into('<I', part, file_inode_offset + 4, 16)
    struct.pack_into('<H', part, file_inode_offset + 26, 1)
    # Extents en i_block (offset 40) para inodo 12 (hello.txt) -> bloque fisico 11
    struct.pack_into('<HHHHI', part, file_inode_offset + 40, 0xF30A, 1, 4, 0, 0)
    struct.pack_into('<IHHI', part, file_inode_offset + 52, 0, 1, 0, 11)
    
    file_data_offset = 11264
    part[file_data_offset : file_data_offset + 16] = b'HELLO EXT4 DATA '
    
    return bytes(part)


def generate_disk_image(output_path: str):
    print(f"[+] Generando imagen forense multipropósito: {output_path}")
    total_sectors = 100000
    
    pmbr = create_protective_mbr(total_sectors)
    gpt_header, gpt_entries = create_gpt_structures(total_sectors)
    
    fat12_part = format_fat12_partition()
    fat16_part = format_fat16_partition()
    fat32_part = format_fat32_partition()
    exfat_part = format_exfat_partition()
    ntfs_part = format_ntfs_partition()
    ext4_part = format_ext4_partition()
    
    disk = bytearray(total_sectors * 512)
    disk[0:512] = pmbr
    disk[512:1024] = gpt_header
    disk[1024 : 1024 + len(gpt_entries)] = gpt_entries
    
    # Copiar particiones a sus LBA correspondientes según GPT
    disk[2048 * 512 : (2048 + 2048) * 512] = fat12_part
    disk[4096 * 512 : (4096 + 10240) * 512] = fat16_part
    disk[14336 * 512 : (14336 + 75664) * 512] = fat32_part
    disk[90000 * 512 : (90000 + 2048) * 512] = exfat_part
    disk[92048 * 512 : (92048 + 2048) * 512] = ntfs_part
    disk[94096 * 512 : (94096 + 2048) * 512] = ext4_part
    
    with open(output_path, 'wb') as f:
        f.write(disk)
        
    print("[OK] Imagen de prueba generada con éxito.")

if __name__ == "__main__":
    generate_disk_image("test_disk.raw")
