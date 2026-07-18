import sys
import os
import shutil

sys.path.insert(0, '.')

from core.data_source import RawImageSource
from core.partition_manager import MBRParser
from fs.fat_parser import FATParser
from fs.exfat_parser import exFATParser
from fs.ntfs_parser import NTFSParser
from fs.ext4_parser import Ext4Parser
from core.shell import NTFSShell

def verify_all_filesystems():
    image_path = "test_disk.raw"
    if not os.path.exists(image_path):
        print(f"[-] Error: No se encuentra la imagen de prueba {image_path}")
        sys.exit(1)
        
    print(f"[+] Iniciando análisis forense en la imagen: {image_path}")
    source = RawImageSource(image_path)
    pm = MBRParser(source)
    
    print(f"[+] Particiones detectadas en la imagen ({len(pm.partitions)}):")
    for idx, part in enumerate(pm.partitions):
        print(f"    Partition {idx}: Type={part.type_code} (Name: {part.type_name}), Start LBA={part.start_lba}, Size={part.size_in_sectors}")
        
    assert len(pm.partitions) == 6
    
    # ------------------ 1. TEST FAT12 ------------------
    print("\n[+] 1. Validando Partición 1 (FAT12)...")
    part_fat12 = pm.partitions[0]
    parser12 = FATParser(source, part_fat12)
    assert parser12.boot_sector.fat_type == 12
    entries12 = parser12.get_directory_entries(0) # 0 es root dir fijo en FAT12/16
    print(f"    Archivos leídos en root directory FAT12:")
    for e in entries12:
        print(f"      - {e.name} (Tamaño: {e.size}, Clúster: {e.start_cluster}, Borrado: {e.is_deleted})")
    
    # Buscar HELLO.TXT
    hello12 = next((e for e in entries12 if e.name == "HELLO.TXT"), None)
    assert hello12 is not None
    assert hello12.size == 16
    # Leer datos
    chain12 = parser12.get_fat_chain(hello12.start_cluster)
    data12 = bytearray()
    for c in chain12:
        offset = parser12.get_cluster_offset(c)
        data12.extend(source.read(offset, parser12.get_cluster_size()))
    content12 = bytes(data12[:hello12.size])
    print(f"    Contenido de HELLO.TXT: {content12}")
    assert content12 == b"HELLO FAT12 DATA"
    
    # Buscar _ELETED.TXT
    deleted12 = next((e for e in entries12 if e.name == "_ELETED.TXT"), None)
    assert deleted12 is not None
    assert deleted12.is_deleted is True
    assert deleted12.size == 24
    
    # ------------------ 2. TEST FAT16 ------------------
    print("\n[+] 2. Validando Partición 2 (FAT16)...")
    part_fat16 = pm.partitions[1]
    parser16 = FATParser(source, part_fat16)
    assert parser16.boot_sector.fat_type == 16
    entries16 = parser16.get_directory_entries(0)
    print(f"    Archivos leídos en root directory FAT16:")
    for e in entries16:
        print(f"      - {e.name} (Tamaño: {e.size}, Clúster: {e.start_cluster}, Borrado: {e.is_deleted})")
        
    hello16 = next((e for e in entries16 if e.name == "HELLO.TXT"), None)
    assert hello16 is not None
    chain16 = parser16.get_fat_chain(hello16.start_cluster)
    data16 = bytearray()
    for c in chain16:
        data16.extend(source.read(parser16.get_cluster_offset(c), parser16.get_cluster_size()))
    content16 = bytes(data16[:hello16.size])
    print(f"    Contenido de HELLO.TXT: {content16}")
    assert content16 == b"HELLO FAT16 DATA"
    
    # Buscar _ELETED.TXT en FAT16
    deleted16 = next((e for e in entries16 if e.name == "_ELETED.TXT"), None)
    assert deleted16 is not None
    assert deleted16.is_deleted is True
    assert deleted16.size == 24
    
    # ------------------ 3. TEST FAT32 ------------------
    print("\n[+] 3. Validando Partición 3 (FAT32)...")
    part_fat32 = pm.partitions[2]
    parser32 = FATParser(source, part_fat32)
    assert parser32.boot_sector.fat_type == 32
    # El cluster root de FAT32 es 2
    entries32 = parser32.get_directory_entries(2)
    print(f"    Archivos leídos en root directory FAT32:")
    for e in entries32:
        print(f"      - {e.name} (Tamaño: {e.size}, Clúster: {e.start_cluster}, Borrado: {e.is_deleted})")
        
    notes32 = next((e for e in entries32 if e.name == "NOTES.TXT"), None)
    assert notes32 is not None
    chain32 = parser32.get_fat_chain(notes32.start_cluster)
    data32 = bytearray()
    for c in chain32:
        data32.extend(source.read(parser32.get_cluster_offset(c), parser32.get_cluster_size()))
    content32 = bytes(data32[:notes32.size])
    print(f"    Contenido de NOTES.TXT: {content32}")
    assert content32 == b"HELLO FAT32 DATA"
    
    # Buscar _ELETED.TXT en FAT32
    deleted32 = next((e for e in entries32 if e.name == "_ELETED.TXT"), None)
    assert deleted32 is not None
    assert deleted32.is_deleted is True
    assert deleted32.size == 24
    
    # ------------------ 4. TEST exFAT ------------------
    print("\n[+] 4. Validando Partición 4 (exFAT)...")
    part_exfat = pm.partitions[3]
    parserexfat = exFATParser(source, part_exfat)
    # Directorio raiz exFAT cluster 2
    entriesexfat = parserexfat.get_directory_entries(2)
    print(f"    Archivos leídos en root directory exFAT:")
    for e in entriesexfat:
        print(f"      - {e.name} (Tamaño: {e.size}, Clúster: {e.start_cluster}, Borrado: {e.is_deleted}, NoFatChain: {e.no_fat_chain})")
        
    exfat_file = next((e for e in entriesexfat if e.name == "exfat.dat"), None)
    assert exfat_file is not None
    chainexfat = parserexfat.get_fat_chain(exfat_file.start_cluster, exfat_file.no_fat_chain, exfat_file.size)
    dataexfat = bytearray()
    for c in chainexfat:
        dataexfat.extend(source.read(parserexfat.get_cluster_offset(c), parserexfat.get_cluster_size()))
    contentexfat = bytes(dataexfat[:exfat_file.size])
    print(f"    Contenido de exfat.dat: {contentexfat}")
    # Buscar deleted.dat
    deletedexfat = next((e for e in entriesexfat if e.name == "deleted.dat"), None)
    assert deletedexfat is not None
    assert deletedexfat.is_deleted is True
    assert deletedexfat.size == 24
    
    # ------------------ 5. TEST NTFS ------------------
    print("\n[+] 5. Validando Partición 5 (NTFS)...")
    part_ntfs = pm.partitions[4]
    parserntfs = NTFSParser(source, part_ntfs)
    
    # Escanear primeros registros buscando archivos pertenecientes al root id 5
    print("    Escaneando registros MFT apuntando a Root ID 5:")
    hello_ntfs_record = None
    deleted_ntfs_record = None
    
    # Imprimir info de la MFT
    print(f"      NTFS MFT Start Offset: {parserntfs.vbr.get_mft_offset()}")
    print(f"      Bytes per MFT Record: {parserntfs.vbr.bytes_per_mft_record}")
    
    for i in range(40):
        try:
            mft_start_offset = parserntfs.vbr.get_mft_offset()
            record_offset = mft_start_offset + (i * parserntfs.vbr.bytes_per_mft_record)
            raw = source.read(record_offset, 4)
            # Solo si contiene algo de interes imprimimos
            if raw != b'\x00\x00\x00\x00':
                print(f"      MFT {i} en offset {record_offset}: signature={raw}")
                
            rec = parserntfs.get_mft_record(i)
            if rec.signature != 'FILE':
                continue
            rec.parse_attributes()
            if rec.file_name:
                print(f"        Encontrado archivo: MFT {i}: '{rec.file_name}', parent={rec.parent_mft_id}")
            if rec.parent_mft_id == 5 and rec.file_name:
                if rec.file_name == "hello.txt":
                    hello_ntfs_record = rec
                elif rec.file_name == "deleted.txt":
                    deleted_ntfs_record = rec
        except Exception as e:
            err_str = str(e).encode('ascii', errors='replace').decode('ascii')
            print(f"      MFT {i} error: {err_str}")
            
    assert hello_ntfs_record is not None
    assert deleted_ntfs_record is not None
    assert deleted_ntfs_record.is_in_use() is False
    
    # Extraer el contenido del stream DATA residente de hello.txt
    for s in hello_ntfs_record.data_streams:
        if not s['name']: # Default stream
            data_content = s['content'] if s['is_resident'] else parserntfs.read_data_runs(s['runs'], s['size'])
            print(f"    Contenido de hello.txt: {data_content}")
            assert data_content == b"HELLO NTFS DATA"
            
    # ------------------ 6. TEST Ext4 ------------------
    print("\n[+] 6. Validando Partición 6 (Ext4)...")
    part_ext4 = pm.partitions[5]
    parserext4 = Ext4Parser(source, part_ext4)
    # Listar root directory inode 2
    entriesext4 = parserext4.get_directory_entries(2)
    print(f"    Archivos leídos en root directory Ext4:")
    for e in entriesext4:
        print(f"      - Inode: {e['inode']}, Type: {e['type']}, Name: {e['name']}")
        
    hello_ext4 = next((e for e in entriesext4 if e['name'] == "hello.txt"), None)
    assert hello_ext4 is not None
    
    # Leer datos de inodo 12
    inode12 = parserext4.get_inode(12)
    blocks = parserext4.get_inode_data_blocks(inode12)
    dataext4 = bytearray()
    for b in blocks:
        # offset del bloque = start_offset + b * block_size
        # block_size de nuestro test es 1024
        offset = part_ext4.start_offset + b * 1024
        dataext4.extend(source.read(offset, 1024))
        
    contentext4 = bytes(dataext4[:16])
    print(f"    Contenido de hello.txt en Ext4: {contentext4}")
    assert contentext4 == b"HELLO EXT4 DATA "
    
    source.close()
    
    # ------------------ 7. TEST CARVING (DISCO Y PARTICIÓN) ------------------
    print("\n[+] 7. Validando Módulo de File Carving (Disco y Partición)...")
    
    source = RawImageSource("test_disk.raw")
    shell = NTFSShell(source, pm)
    
    test_out_dir = "scratch/carve_test_out"
    if os.path.exists(test_out_dir):
        shutil.rmtree(test_out_dir)
    os.makedirs(test_out_dir, exist_ok=True)
        
    # Test A: Carving de todo el disco (sin seleccionar partición)
    # Buscamos solo tipo 'jpg' para ir rápido
    print("    -> Ejecutando carve en toda la imagen de disco...")
    shell.do_carve(f"{test_out_dir} jpg")
    
    # Verificar que el archivo JPEG fue recuperado
    files = os.listdir(test_out_dir)
    print(f"       Archivos recuperados de todo el disco: {files}")
    assert len(files) >= 1
    jpg_files = [f for f in files if f.endswith(".jpg")]
    assert len(jpg_files) >= 1
    
    # Leer el contenido del archivo carved y verificar que tiene nuestra firma y texto
    with open(os.path.join(test_out_dir, jpg_files[0]), 'rb') as f:
        carved_data = f.read()
    assert b'_JPEG_' in carved_data
    print("    [OK] Carving de disco completo validado.")
    
    # Test B: Carving de una partición (seleccionamos la partición FAT32)
    # Reiniciar directorio
    shutil.rmtree(test_out_dir)
    os.makedirs(test_out_dir, exist_ok=True)
    
    shell.do_select("2") # Seleccionar Partición 2 (FAT32)
    print("    -> Ejecutando carve en la partición FAT32...")
    shell.do_carve(f"{test_out_dir} jpg")
    
    files_part = os.listdir(test_out_dir)
    print(f"       Archivos recuperados de la partición FAT32: {files_part}")
    assert len(files_part) >= 1
    jpg_files_part = [f for f in files_part if f.endswith(".jpg")]
    assert len(jpg_files_part) >= 1
    
    # ------------------ 8. TEST DE COMANDO DELETED Y RECOVERY ------------------
    print("\n[+] 8. Validando Comando 'deleted' y Recuperación Basada en Metadatos...")
    
    # FAT32 (Partición 2, índice 2 de pm.partitions)
    shell.do_select("2")
    shell.fat_files_cache = []
    shell.do_deleted("")
    
    # Verificar que _ELETED.TXT está en la caché de FAT y listado
    print(f"       Caché FAT cargada por 'deleted': {[e.name for e in shell.fat_files_cache]}")
    deleted_entry = next((e for e in shell.fat_files_cache if e.name == "_ELETED.TXT"), None)
    assert deleted_entry is not None
    assert deleted_entry.is_deleted is True
    
    # Probar recuperación usando recover <id>
    idx_deleted = shell.fat_files_cache.index(deleted_entry)
    rec_dest = "scratch/rec_fat32_deleted.txt"
    if os.path.exists(rec_dest):
        os.remove(rec_dest)
    shell.do_recover(f"{idx_deleted} {rec_dest}")
    assert os.path.exists(rec_dest)
    with open(rec_dest, 'rb') as f:
        rec_data = f.read()
    print(f"       Archivo FAT32 recuperado: {rec_data}")
    assert len(rec_data) == 24
    os.remove(rec_dest)
    
    # NTFS (Partición 4, índice 4 de pm.partitions)
    shell.do_select("4")
    # Capturar la salida estándar para verificar si deleted.txt aparece
    import io
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        shell.do_deleted("40")
        output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
        
    print("       Salida de 'deleted' en NTFS:")
    print("\n".join("         " + line for line in output.strip().split("\n")))
    assert "deleted.txt" in output.lower()
    
    # Extraer el ID MFT del archivo deleted.txt de la salida del comando o buscarlo manualmente
    ntfs_deleted_id = None
    for i in range(40):
        try:
            rec = shell.current_parser.get_mft_record(i)
            if rec.signature == 'FILE':
                rec.parse_attributes()
                if rec.file_name == "deleted.txt" and not rec.is_in_use():
                    ntfs_deleted_id = i
                    break
        except Exception:
            pass
            
    assert ntfs_deleted_id is not None
    rec_ntfs_dest = "scratch/rec_ntfs_deleted.txt"
    if os.path.exists(rec_ntfs_dest):
        os.remove(rec_ntfs_dest)
        
    shell.do_recover(f"{ntfs_deleted_id} {rec_ntfs_dest}")
    assert os.path.exists(rec_ntfs_dest)
    with open(rec_ntfs_dest, 'rb') as f:
        rec_ntfs_data = f.read()
    print(f"       Archivo NTFS recuperado: {rec_ntfs_data}")
    assert len(rec_ntfs_data) > 0
    os.remove(rec_ntfs_dest)

    # ------------------ 9. TEST DE CARVING CONFIGURABLE Y SIGNATURES.CONF ------------------
    print("\n[+] 9. Validando File Carving Configurable y Archivo de Configuración...")
    
    config_carve_out = "scratch/carve_config_out"
    if os.path.exists(config_carve_out):
        shutil.rmtree(config_carve_out)
    os.makedirs(config_carve_out, exist_ok=True)
    
    # Ejecutar carve con --max-size 6 bytes
    shell.do_select("2")
    print("    -> Ejecutando carve con --max-size 6...")
    shell.do_carve(f"{config_carve_out} jpg --max-size 6")
    
    files_config = os.listdir(config_carve_out)
    print(f"       Archivos recuperados con limitación: {files_config}")
    assert len(files_config) >= 1
    
    # Leer el tamaño del archivo recuperado
    with open(os.path.join(config_carve_out, files_config[0]), 'rb') as f:
        carved_data = f.read()
    print(f"       Tamaño del archivo recuperado con max-size=6: {len(carved_data)} bytes")
    assert len(carved_data) == 6
    
    # Validar que signatures.conf existe en el directorio del proyecto
    assert os.path.exists("signatures.conf")
    print("    [OK] signatures.conf se creó automáticamente con éxito.")
    
    # Limpieza del Test 9
    shutil.rmtree(config_carve_out)

    # ------------------ 10. TEST DE AYUDA INTERACTIVA Y AUTOCOMPLETADO ------------------
    print("\n[+] 10. Validando Ayuda Interactiva (?) y Autocompletado de Rutas/Opciones...")
    
    # 10.1 Probar "carve ?"
    sys.stdout = io.StringIO()
    try:
        shell.do_carve("?")
        help_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de 'carve ?':")
    print("\n".join("         " + line for line in help_output.strip().split("\n")[:4]))
    assert "Realiza File Carving" in help_output
    
    # 10.2 Probar autocompletado de opciones en complete_carve
    carve_suggestions = shell.complete_carve("--d", "carve --d", 6, 9)
    print(f"       Sugerencias para 'carve --d': {carve_suggestions}")
    assert "--disk" in carve_suggestions
    
    # 10.3 Probar autocompletado de rutas locales del host en complete_recover (segundo parámetro)
    recover_suggestions = shell.complete_recover("scra", "recover 0 scra", 10, 14)
    print(f"       Sugerencias para 'recover 0 scra': {recover_suggestions}")
    assert any("scratch" in s for s in recover_suggestions)
    
    print("    [OK] Ayuda interactiva y autocompletado inteligente validados.")

    # ------------------ 11. TEST DE MENÚ DE AYUDA GENERAL PERSONALIZADO ------------------
    print("\n[+] 11. Validando Menú de Ayuda General Personalizado (help / ?)...")
    sys.stdout = io.StringIO()
    try:
        shell.do_help("")
        gen_help_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de 'help':")
    print("\n".join("         " + line for line in gen_help_output.strip().split("\n")[:6]))
    assert "COMANDOS DISPONIBLES EN EL SHELL FORENSE" in gen_help_output
    assert "COMANDOS GENERALES Y DE NAVEGACIÓN:" in gen_help_output
    print("    [OK] Menú de ayuda general personalizado validado.")

    # ------------------ 12. TEST DE LOCALIZACIÓN DE AYUDA (BILINGÜE) ------------------
    print("\n[+] 12. Validando Localización de Ayuda (Bilingüe - English)...")
    from core.i18n import set_language
    
    set_language("en")
    sys.stdout = io.StringIO()
    try:
        shell.do_carve("?")
        en_help_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
        set_language("es")
        
    print("       Salida de 'carve ?' en inglés:")
    print("\n".join("         " + line for line in en_help_output.strip().split("\n")[:4]))
    assert "Performs automated File Carving" in en_help_output
    assert "Usage:" in en_help_output
    print("    [OK] Localización de docstrings y ayuda contextual validados correctamente.")

    # ------------------ 13. TEST DE INICIALIZACIÓN VACÍA Y COMANDO OPEN ------------------
    print("\n[+] 13. Validando Inicialización sin Imagen y Comando 'open'...")
    
    # 13.1 Inicializar shell vacío
    shell_empty = NTFSShell(None, None)
    print(f"       Prompt inicial sin imagen: '{shell_empty.prompt}'")
    assert shell_empty.prompt == "Forense [Sin Imagen] > "
    
    # 13.2 Validar robustez de comandos sin imagen cargada
    sys.stdout = io.StringIO()
    try:
        shell_empty.do_select("0")
        empty_select_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print(f"       Salida de select sin imagen: {empty_select_output.strip()}")
    assert "No hay ninguna imagen cargada" in empty_select_output
    
    # 13.3 Cargar imagen con el comando open
    shell_empty.do_open("test_disk.raw")
    assert shell_empty.data_source is not None
    assert shell_empty.mbr_parser is not None
    print(f"       Prompt después de 'open': '{shell_empty.prompt}'")
    assert shell_empty.prompt == "Forense > "
    assert len(shell_empty.mbr_parser.partitions) == 6
    
    # ------------------ 14. TEST DE DETECCIÓN DE BITLOCKER ------------------
    print("\n[+] 14. Validando Detección de Cifrado BitLocker (Firma -FVE-FS-)...")
    
    # 14.1 Re-abrir para BitLocker Test
    shell_empty.do_open("test_disk.raw")
    
    # Mockear lectura de sector físico de prueba con firma BitLocker
    original_read = shell_empty.data_source.read
    def mock_read_bitlocker(offset, size):
        if offset == 999999 * 512:
            buf = bytearray(512)
            buf[3:11] = b'-FVE-FS-'
            buf[510:512] = b'\x55\xAA'
            return bytes(buf)
        return original_read(offset, size)
    shell_empty.data_source.read = mock_read_bitlocker
    
    # 14.2 Validar identify sector con firma BitLocker
    sys.stdout = io.StringIO()
    try:
        shell_empty.do_identify("sector 999999")
        identify_bitlocker_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print(f"       Salida de identify sector (BitLocker): {identify_bitlocker_out.strip()}")
    assert "BitLocker" in identify_bitlocker_out
    
    # 14.3 Validar select partition con BitLocker VBR
    shell_empty.mbr_parser.partitions[0].start_lba = 999999
    sys.stdout = io.StringIO()
    try:
        shell_empty.do_select("0")
        select_bitlocker_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de select partition (BitLocker):")
    print("\n".join("         " + line for line in select_bitlocker_out.strip().split("\n") if line))
    assert "BitLocker" in select_bitlocker_out
    assert shell_empty.current_parser is None
    
    # Restaurar y limpiar
    shell_empty.data_source.close()
    print("    [OK] Detección de BitLocker en identificación y montado de particiones validada.")

    # ------------------ 15. TEST DE HISTORIAL DE COMANDOS ------------------
    print("\n[+] 15. Validando Historial de Comandos (Comando 'history')...")
    shell_history = NTFSShell(None, None)
    
    try:
        import readline
        readline.add_history("test_command_forense")
        
        sys.stdout = io.StringIO()
        try:
            shell_history.do_history("")
            history_output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
            
        print("       Salida de history en test:")
        print("\n".join("         " + line for line in history_output.strip().split("\n") if line))
        assert "test_command_forense" in history_output
        print("    [OK] Historial de comandos verificado exitosamente.")
    except ImportError:
        print("    [i] Saltando test de readline (no disponible en este entorno).")

    # ------------------ 16. TEST DE DISKINFO ------------------
    print("\n[+] 16. Validando Comando 'diskinfo' (Reporte Maestro de Disco)...")
    shell_diskinfo = NTFSShell(source, MBRParser(source))
    
    sys.stdout = io.StringIO()
    try:
        shell_diskinfo.do_diskinfo("")
        diskinfo_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
        
    print("       Salida de diskinfo en test:")
    print("\n".join("         " + line for line in diskinfo_output.strip().split("\n") if line))
    assert "INFORMACIÓN DE LA IMAGEN" in diskinfo_output
    assert "test_disk.raw" in diskinfo_output
    assert "GPT" in diskinfo_output
    assert "Geometría lógica" in diskinfo_output
    assert "Cilindros" in diskinfo_output
    print("    [OK] Comando 'diskinfo' verificado exitosamente.")

    # ------------------ 17. TEST DE PARTITIONS -V Y UNALLOCATED SPACE ------------------
    print("\n[+] 17. Validando Comando 'partitions -v' y Espacio no Asignado...")
    shell_parts = NTFSShell(source, MBRParser(source))
    
    sys.stdout = io.StringIO()
    try:
        shell_parts.do_partitions("")
        parts_std_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de partitions estándar en test:")
    print("\n".join("         " + line for line in parts_std_out.strip().split("\n") if line))
    assert "Espacio sin particionar" in parts_std_out
    
    sys.stdout = io.StringIO()
    try:
        shell_parts.do_partitions("-v")
        parts_verbose_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de partitions -v en test:")
    print("\n".join("         " + line for line in parts_verbose_out.strip().split("\n")[:20] if line) + "\n         ...")
    assert "ANÁLISIS EXPLICATIVO" in parts_verbose_out
    assert "GPT Header" in parts_verbose_out
    print("    [OK] Desglose didáctico y espacio sin particionar validados correctamente.")

    # ------------------ 18. TEST DE VBRINFO (VOLÚMENES Y FILESYSTEMS) ------------------
    print("\n[+] 18. Validando Comando 'vbrinfo' (Estructura de Filesystems)...")
    shell_vbr = NTFSShell(source, MBRParser(source))
    
    sys.stdout = io.StringIO()
    try:
        shell_vbr.do_vbrinfo("")
        vbr_no_sel_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    assert "No hay ninguna partición seleccionada" in vbr_no_sel_out
    
    shell_vbr.do_select("2")
    sys.stdout = io.StringIO()
    try:
        shell_vbr.do_vbrinfo("")
        vbr_fat32_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de vbrinfo para FAT32 en test:")
    print("\n".join("         " + line for line in vbr_fat32_out.strip().split("\n")[:25] if line))
    assert "ANÁLISIS EXPLICATIVO" in vbr_fat32_out
    assert "BIOS Parameter Block" in vbr_fat32_out
    assert "Sectores Reservados" in vbr_fat32_out
    
    shell_vbr.do_select("4")
    sys.stdout = io.StringIO()
    try:
        shell_vbr.do_vbrinfo("")
        vbr_ntfs_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    print("       Salida de vbrinfo para NTFS en test:")
    print("\n".join("         " + line for line in vbr_ntfs_out.strip().split("\n")[:25] if line))
    assert "ANÁLISIS EXPLICATIVO" in vbr_ntfs_out
    assert "Clúster de inicio $MFT" in vbr_ntfs_out or "Apunta al inicio físico" in vbr_ntfs_out
    
    print("    [OK] Desglose didáctico de VBR de volúmenes validado correctamente.")

    # ------------------ 19. TEST DE LISTADO DE DISPOSITIVOS DEL HOST ------------------
    print("\n[+] 19. Validando Listado de Dispositivos del Host (Comando 'open' sin argumentos)...")
    shell_devlist = NTFSShell(None, None)
    
    sys.stdout = io.StringIO()
    try:
        shell_devlist.do_open("")
        devlist_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
        
    print("       Salida de listado de dispositivos en test:")
    print("\n".join("         " + line for line in devlist_out.strip().split("\n")[:20] if line))
    assert "DISPOSITIVOS DE ALMACENAMIENTO" in devlist_out
    assert "Discos Físicos" in devlist_out or "Dispositivos de Bloque" in devlist_out
    print("    [OK] Listado de dispositivos del host validado correctamente.")

    # ------------------ 20. TEST DE CLUSTERMAP (DISTRIBUCIÓN VISUAL) ------------------
    print("\n[+] 20. Validando Comando 'clustermap' (Distribución Visual)...")
    shell_map = NTFSShell(source, MBRParser(source))
    
    sys.stdout = io.StringIO()
    try:
        shell_map.do_clustermap("")
        map_no_sel_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    assert "No hay ninguna partición seleccionada" in map_no_sel_out
    
    shell_map.do_select("4") # NTFS
    sys.stdout = io.StringIO()
    try:
        shell_map.do_clustermap("")
        map_out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
        
    print("       Salida de clustermap en test:")
    print("\n".join("         " + line for line in map_out.strip().split("\n")[:25] if line))
    assert "DISTRIBUCIÓN VISUAL DE CLÚSTERES" in map_out
    assert "Mapa del Volumen" in map_out
    assert "LEYENDA" in map_out
    print("    [OK] Distribución visual de clústeres validada correctamente.")

    # Limpieza final
    source.close()
    
    print("\n[OK] ¡TODAS LAS PARTICIONES, ARCHIVOS, CARVING, RECOVERY, CONFIGURACIONES, AUTOCOMPLETADO, AYUDA GENERAL, TRADUCCIONES, APERTURA, BITLOCKER, HISTORIAL, DISKINFO, PARTITIONS EXPLICATIVO, VBRINFO, LISTADO DE DISPOSITIVOS Y MAPA DE CLÚSTERES SE VALIDARON CORRECTAMENTE EN LA IMAGEN!")

if __name__ == "__main__":
    verify_all_filesystems()
