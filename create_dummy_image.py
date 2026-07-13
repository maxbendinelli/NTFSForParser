import struct
import os

def create_dummy_image(filename="test.dd"):
    print(f"[*] Creando imagen de prueba: {filename}")
    
    # Tamaño de sector
    sector_size = 512
    # Start LBA para la partición
    start_lba = 2048
    
    # 1. Crear el MBR (Sector 0)
    mbr = bytearray(sector_size)
    
    # Firma MBR
    mbr[510] = 0x55
    mbr[511] = 0xAA
    
    # Entrada de partición 1 (Offset 446)
    # bootable(1), CHS(3), type(1), CHS(3), start_lba(4), size(4)
    # 0x80, 0,0,0, 0x07 (NTFS), 0,0,0, 2048, 10240
    part1_entry = struct.pack('<B3sB3sII', 0x80, b'\x00\x00\x00', 0x07, b'\x00\x00\x00', start_lba, 10240)
    mbr[446:446+16] = part1_entry
    
    # 2. Crear el VBR de NTFS (Sector 2048)
    vbr = bytearray(sector_size)
    # Jump instruction + OEM ID
    vbr[0:3] = b'\xEB\x52\x90'
    vbr[3:11] = b'NTFS    '
    
    # BPB
    # Bytes por sector: 512
    vbr[11:13] = struct.pack('<H', 512)
    # Sectores por clúster: 8
    vbr[13:14] = struct.pack('<B', 8)
    
    # MFT start cluster: 4
    vbr[48:56] = struct.pack('<Q', 4)
    # MFT mirror start cluster: 16
    vbr[56:64] = struct.pack('<Q', 16)
    # Clusters per MFT record: 1024 bytes -> -10 -> 0xF6
    vbr[64:65] = struct.pack('<b', -10)
    
    # 3. Escribir a disco
    with open(filename, 'wb') as f:
        # Escribir MBR
        f.write(mbr)
        
        # Rellenar hasta el sector 2048
        f.seek(start_lba * sector_size)
        
        # Escribir VBR
        f.write(vbr)
        
        # Escribir el tamaño total (10 MB aprox)
        f.seek((start_lba + 10240) * sector_size - 1)
        f.write(b'\x00')
        
    print("[+] Imagen creada con éxito.")

if __name__ == "__main__":
    create_dummy_image()
