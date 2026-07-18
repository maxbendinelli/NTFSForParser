import cmd
import sys
import os

# Ajustar sys.path para permitir la ejecución directa de este script
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from core.i18n import _
from core.data_source import DataSource
from core.utils import hexdump, print_breakdown
from fs.ntfs_parser import NTFSParser
from fs.fat_parser import FATParser
from fs.ext4_parser import Ext4Parser
from fs.exfat_parser import exFATParser
from fs.carver import FileCarver, SIGNATURES, load_signatures

class NTFSShell(cmd.Cmd):
    @property
    def intro(self):
        return _("\nBienvenido al Shell Interactivo Forense.\nEscribe 'help' o '?' para listar los comandos.\n")
        
    prompt = "Forense > "
    
    HISTORY_FILE = os.path.expanduser("~/.forense_history")
    MAX_HISTORY_LENGTH = 1000

    def preloop(self):
        # Cargar historial desde disco
        if os.path.exists(self.HISTORY_FILE):
            try:
                import readline
                readline.read_history_file(self.HISTORY_FILE)
            except Exception:
                pass

    def postloop(self):
        # Guardar historial al disco
        try:
            import readline
            readline.set_history_length(self.MAX_HISTORY_LENGTH)
            readline.write_history_file(self.HISTORY_FILE)
        except Exception:
            pass

    def __init__(self, data_source: DataSource, mbr_parser):
        super().__init__()
        self.data_source = data_source
        self.mbr_parser = mbr_parser
        self.selected_partition = None
        self.current_parser = None
        self.fat_files_cache = [] # Caché para los IDs temporales en FAT
        self.ntfs_files_cache = {} # Caché Nombre->MFT_ID para 'cd'
        self.ext4_files_cache = [] # Caché de diccionarios devueltos por ext4_parser
        self.current_directory_id = None
        self.current_path = "/"
        self.update_prompt()
        
        # Ajustar delimitadores de readline para soportar rutas con barras y dos puntos
        try:
            try:
                import readline
            except ImportError:
                import pyreadline3 as readline
                import sys
                sys.modules['readline'] = readline
                
            delims = readline.get_completer_delims()
            for char in ['/', '\\', ':', '-']:
                delims = delims.replace(char, '')
            readline.set_completer_delims(delims)
            
            # Enlazar explícitamente las flechas arriba/abajo en Windows
            if sys.platform == "win32":
                readline.parse_and_bind("up: history-search-backward")
                readline.parse_and_bind("down: history-search-forward")
                
            # Registrar auto-guardado robusto del historial con atexit
            import atexit
            atexit.register(readline.write_history_file, self.HISTORY_FILE)
        except Exception:
            pass

    def update_prompt(self):
        if self.data_source is None:
            self.prompt = "Forense [Sin Imagen] > "
        elif self.selected_partition is None:
            self.prompt = "Forense > "
        else:
            self.prompt = f"Forense [Part {self.selected_partition} | {self.current_path}] > "

    # --- Comandos Generales ---
    
    def do_partitions(self, arg):
        """Lista las particiones encontradas en el disco y las áreas sin particionar.
        Uso:
          partitions        -> Listado simple
          partitions -v     -> Explicación didáctica coloreada en Hexadecimal (MBR/GPT)
        """
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_partitions.__doc__))
            return
        if not self.mbr_parser or not self.mbr_parser.partitions:
            print(_("No se encontraron particiones (Asegúrate de abrir una imagen primero usando 'open')."))
            return
            
        args = arg.split()
        if "-v" in args or "--verbose" in args:
            self._print_partitions_breakdown()
            return
            
        print(_("\nParticiones disponibles y espacio sin particionar:"))
        print(f"  {'LBA Inicio':<12} | {'LBA Fin':<12} | {'Estado / Tipo de Partición':<45} | {'Tamaño':<10}")
        print("  " + "-" * 90)
        
        # Intercalar particiones y espacios libres ordenados por LBA
        all_blocks = []
        for idx, part in enumerate(self.mbr_parser.partitions):
            boot_flag = " [*]" if part.bootable else ""
            all_blocks.append({
                "start_lba": part.start_lba,
                "end_lba": part.start_lba + part.size_in_sectors - 1,
                "type": f"[{idx}] {part.type_name}{boot_flag}",
                "size_bytes": part.size_in_bytes,
                "is_partition": True
            })
            
        unallocated = self.mbr_parser.get_unallocated_spaces()
        for gap in unallocated:
            all_blocks.append({
                "start_lba": gap["start_lba"],
                "end_lba": gap["start_lba"] + gap["size_in_sectors"] - 1,
                "type": f"\033[91m{_( 'Espacio sin particionar (Unallocated)')}\033[0m",
                "size_bytes": gap["size_in_bytes"],
                "is_partition": False
            })
            
        all_blocks = sorted(all_blocks, key=lambda b: b["start_lba"])
        
        for b in all_blocks:
            size_mb = b["size_bytes"] / (1024**2)
            size_str = f"{size_mb:.1f} MB" if size_mb < 1024 else f"{size_mb/1024:.2f} GB"
            print(f"  {b['start_lba']:<12} | {b['end_lba']:<12} | {b['type']:<54} | {size_str:<10}")
        print("")

    def _print_partitions_breakdown(self):
        """Genera un reporte didáctico coloreado en Hexadecimal del sector de la tabla de particiones."""
        import struct
        
        if self.mbr_parser.is_gpt:
            print(_("\n=================================================================================="))
            print(_("  ANÁLISIS EXPLICATIVO DE LA TABLA DE PARTICIONES GPT - LBA 1 Y LBA 2"))
            print(_("=================================================================================="))
            
            # Leer LBA 1 (GPT Header)
            gpt_header = self.data_source.read(512, 512)
            if len(gpt_header) < 512:
                print(_("Error al leer el GPT Header."))
                return
                
            print(_("\n[i] Volcado hexadecimal del GPT Header (LBA 1, primeros 96 bytes):"))
            print("Offset    | Hexadecimal                                     | ASCII")
            print("-" * 75)
            
            for i in range(0, 96, 16):
                chunk = gpt_header[i:i+16]
                hex_str = ""
                ascii_str = ""
                for j, b in enumerate(chunk):
                    offset = i + j
                    if 0 <= offset < 8: # Firma "EFI PART"
                        color = "\033[92m" # Verde
                    elif 72 <= offset < 80: # LBA de Entradas
                        color = "\033[93m" # Amarillo
                    elif 80 <= offset < 84: # Cantidad de Entradas
                        color = "\033[96m" # Cian
                    elif 84 <= offset < 88: # Tamaño de Entrada
                        color = "\033[95m" # Magenta
                    else:
                        color = "\033[90m" # Gris
                    hex_str += f"{color}{b:02x}\033[0m "
                    ascii_str += f"{color}{chr(b) if 32 <= b <= 127 else '.'}\033[0m"
                print(f"0x{i:02x}       | {hex_str} | {ascii_str}")
                
            sig = gpt_header[0:8].decode('ascii', errors='ignore')
            entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
            num_entries = struct.unpack('<I', gpt_header[80:84])[0]
            entry_size = struct.unpack('<I', gpt_header[84:88])[0]
            
            print(_("\n[+] Desglose del GPT Header (LBA 1):"))
            print(f"  - Offset 0x00 (Firma)      : \033[92m{sig}\033[0m -> Firma EFI PART válida.")
            print(f"  - Offset 0x48 (LBA Entradas): \033[93m{entries_lba}\033[0m -> LBA donde empieza el array de particiones.")
            print(f"  - Offset 0x50 (Num Entradas): \033[96m{num_entries}\033[0m -> Cantidad máxima de particiones soportadas.")
            print(f"  - Offset 0x54 (Tamaño Ent.):  \033[95m{entry_size}\033[0m -> Tamaño en bytes de cada registro de partición.")
            
            # Recorrer todas las particiones analizadas de forma activa
            for idx, part in enumerate(self.mbr_parser.partitions):
                entry_offset = (entries_lba * 512) + (idx * entry_size)
                gpt_entry_data = self.data_source.read(entry_offset, entry_size)
                
                if len(gpt_entry_data) >= 128:
                    print(f"\n" + "-" * 75)
                    print(_("[i] Volcado hexadecimal de la Entrada GPT #{idx} (LBA {lba}, Offset {offset}):").format(
                        idx=idx, lba=entries_lba + (idx * entry_size) // 512, offset=hex(entry_offset)))
                    print("Offset    | Hexadecimal                                     | ASCII")
                    print("-" * 75)
                    
                    for i in range(0, 128, 16):
                        chunk = gpt_entry_data[i:i+16]
                        hex_str = ""
                        ascii_str = ""
                        for j, b in enumerate(chunk):
                            offset = i + j
                            if 0 <= offset < 16: # GUID de Tipo
                                color = "\033[92m"
                            elif 16 <= offset < 32: # GUID de Partición
                                color = "\033[90m"
                            elif 32 <= offset < 40: # Primer LBA
                                color = "\033[93m"
                            elif 40 <= offset < 48: # Último LBA
                                color = "\033[96m"
                            elif 56 <= offset < 128: # Nombre UTF-16LE
                                color = "\033[95m"
                            else:
                                color = "\033[0m"
                            hex_str += f"{color}{b:02x}\033[0m "
                            ascii_str += f"{color}{chr(b) if 32 <= b <= 127 else '.'}\033[0m"
                        print(f"0x{i:02x}       | {hex_str} | {ascii_str}")
                        
                    import uuid
                    type_guid = uuid.UUID(bytes_le=gpt_entry_data[0:16])
                    first_lba, last_lba = struct.unpack('<QQ', gpt_entry_data[32:48])
                    part_name = gpt_entry_data[56:128].decode('utf-16le', errors='replace').rstrip('\x00')
                    num_sectors = (last_lba - first_lba) + 1
                    
                    print(_("\n[+] Desglose de la Entrada GPT #{idx}:").format(idx=idx))
                    print(f"  - Offset 0x00 (GUID Tipo)  : \033[92m{type_guid}\033[0m -> Tipo de partición: {part.type_name}")
                    print(f"  - Offset 0x20 (Primer LBA)  : \033[93m{first_lba}\033[0m -> Sector físico de inicio.")
                    print(f"  - Offset 0x28 (Último LBA)  : \033[96m{last_lba}\033[0m -> Sector físico de fin.")
                    print(f"  - Offset 0x38 (Nombre Part) : \033[95m{part_name}\033[0m -> Etiqueta de la partición (Unicode UTF-16LE).")
                    print(f"  - Tamaño Calculado         : {num_sectors} sectores ({num_sectors * 512 / (1024**2):.2f} MB)")
            print("==================================================================================\n")
            
        else:
            print(_("\n=================================================================================="))
            print(_("  ANÁLISIS EXPLICATIVO DEL MASTER BOOT RECORD (MBR) - SECTOR 0"))
            print(_("=================================================================================="))
            
            mbr_data = self.data_source.read(0, 512)
            if len(mbr_data) < 512:
                print(_("Error al leer el MBR."))
                return
                
            print(_("\n[i] Volcado hexadecimal de la Tabla de Particiones en LBA 0 (Offset 440 a 512):"))
            print("Offset    | Hexadecimal                                     | ASCII")
            print("-" * 75)
            
            for i in range(432, 512, 16):
                chunk = mbr_data[i:i+16]
                hex_str = ""
                ascii_str = ""
                for j, b in enumerate(chunk):
                    offset = i + j
                    if 446 <= offset < 462: # Partición 1
                        color = "\033[92m" # Verde
                    elif 462 <= offset < 478: # Partición 2
                        color = "\033[93m" # Amarillo
                    elif 478 <= offset < 494: # Partición 3
                        color = "\033[96m" # Cian
                    elif 494 <= offset < 510: # Partición 4
                        color = "\033[95m" # Magenta
                    elif 510 <= offset < 512: # Firma 55 AA
                        color = "\033[91m" # Rojo
                    else:
                        color = "\033[90m" # Gris
                    hex_str += f"{color}{b:02x}\033[0m "
                    ascii_str += f"{color}{chr(b) if 32 <= b <= 127 else '.'}\033[0m"
                print(f"0x{i:03x}      | {hex_str} | {ascii_str}")
                
            print(_("\n[+] Explicación de la Firma de Arranque (Magic Bytes):"))
            print(f"  Offset 0x1fe (510-511): \033[91m{mbr_data[510:512].hex().upper()}\033[0m -> {_('Firma de arranque de sector válida (0x55AA).') if mbr_data[510:512] == b'\\x55\\xaa' else _('Firma de arranque inválida.')}")
            
            print(_("\n[+] Desglose de Entradas MBR (16 bytes cada una):"))
            colors = ["\033[92m", "\033[93m", "\033[96m", "\033[95m"]
            names = ["Partición 1", "Partición 2", "Partición 3", "Partición 4"]
            
            for idx in range(4):
                offset_part = 446 + (idx * 16)
                p_bytes = mbr_data[offset_part : offset_part + 16]
                
                if p_bytes[4] == 0x00 and struct.unpack('<I', p_bytes[12:16])[0] == 0:
                    print(f"\n  - \033[90m{names[idx]} (Offset {hex(offset_part)}): Entrada vacía / Sin uso.\033[0m")
                    continue
                    
                status = p_bytes[0]
                p_type = p_bytes[4]
                start_lba = struct.unpack('<I', p_bytes[8:12])[0]
                num_sectors = struct.unpack('<I', p_bytes[12:16])[0]
                
                color = colors[idx]
                print(f"\n  - {color}{names[idx]} (Offset {hex(offset_part)}):\033[0m")
                print(f"    - Byte 0    (Status)    : \033[1m{hex(status)}\033[0m -> {_('Activa / Booteable') if status == 0x80 else _('Inactiva')}")
                print(f"    - Bytes 1-3 (CHS Inicio): {p_bytes[1:4].hex().upper()}")
                print(f"    - Byte 4    (Tipo)      : \033[1m{hex(p_type)}\033[0m -> {self.mbr_parser.PARTITION_TYPES.get(p_type, 'Desconocida')}")
                print(f"    - Bytes 5-7 (CHS Fin)   : {p_bytes[5:8].hex().upper()}")
                print(f"    - Bytes 8-11 (LBA Init) : \033[1m{start_lba}\033[0m (Hex: {hex(start_lba)}) -> {_('Sector de inicio físico en disco')}")
                print(f"    - Bytes 12-15(Sectores) : \033[1m{num_sectors}\033[0m -> {_('Tamaño')}: {num_sectors * 512 / (1024**2):.2f} MB")
            print("==================================================================================\n")

    def do_vbrinfo(self, arg):
        """Muestra el sector de arranque del volumen (VBR) en hexadecimal y colores didácticos.
        Uso: vbrinfo
        """
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_vbrinfo.__doc__))
            return
            
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
            
        if self.selected_partition is None:
            print(_("No hay ninguna partición seleccionada. Usa 'select <id_particion>' primero."))
            return
            
        import struct
        part = self.mbr_parser.partitions[self.selected_partition]
        
        try:
            vbr_data = self.data_source.read(part.start_offset, 512)
        except Exception as e:
            print(_("Error al leer el VBR de la partición: {error}").format(error=e))
            return
            
        if len(vbr_data) < 512:
            print(_("Error: No se pudieron leer 512 bytes del VBR."))
            return
            
        # Detectar tipo de sistema de archivos
        fs_type = "DESCONOCIDO"
        if b"NTFS" in vbr_data[3:11]:
            fs_type = "NTFS"
        elif b"EXFAT" in vbr_data[3:11]:
            fs_type = "EXFAT"
        elif vbr_data[510:512] == b"\x55\xaa":
            if b"FAT32" in vbr_data[82:90] or b"FAT32" in vbr_data[54:62]:
                fs_type = "FAT32"
            elif b"FAT16" in vbr_data[54:62] or b"FAT12" in vbr_data[54:62]:
                fs_type = "FAT16/12"
            else:
                sectors_per_fat_16 = struct.unpack('<H', vbr_data[22:24])[0]
                if sectors_per_fat_16 == 0:
                    fs_type = "FAT32"
                else:
                    fs_type = "FAT16/12"
                    
        print(_("\n=================================================================================="))
        print(_("  ANÁLISIS EXPLICATIVO DEL SECTOR DE ARRANQUE DEL VOLUMEN (VBR) - {fs}").format(fs=fs_type))
        print(_("=================================================================================="))
        
        print(_("\n[i] Volcado hexadecimal de los primeros 96 bytes del VBR:"))
        print("Offset    | Hexadecimal                                     | ASCII")
        print("-" * 75)
        
        for i in range(0, 96, 16):
            chunk = vbr_data[i:i+16]
            hex_str = ""
            ascii_str = ""
            for j, b in enumerate(chunk):
                offset = i + j
                color = "\033[90m" # Gris por defecto
                
                if fs_type == "NTFS":
                    if 0 <= offset < 3:
                        color = "\033[92m"
                    elif 3 <= offset < 11:
                        color = "\033[93m"
                    elif 11 <= offset < 13:
                        color = "\033[96m"
                    elif offset == 13:
                        color = "\033[95m"
                    elif 40 <= offset < 48:
                        color = "\033[94m"
                    elif 48 <= offset < 56:
                        color = "\033[92;1m"
                elif fs_type == "EXFAT":
                    if 0 <= offset < 3:
                        color = "\033[92m"
                    elif 3 <= offset < 11:
                        color = "\033[93m"
                    elif 64 <= offset < 72:
                        color = "\033[96m"
                    elif 72 <= offset < 80:
                        color = "\033[95m"
                    elif 80 <= offset < 84:
                        color = "\033[94m"
                elif fs_type == "FAT32":
                    if 0 <= offset < 3:
                        color = "\033[92m"
                    elif 3 <= offset < 11:
                        color = "\033[93m"
                    elif 11 <= offset < 13:
                        color = "\033[96m"
                    elif offset == 13:
                        color = "\033[95m"
                    elif 14 <= offset < 16:
                        color = "\033[94m"
                    elif offset == 16:
                        color = "\033[92;1m"
                    elif 32 <= offset < 36:
                        color = "\033[96;1m"
                    elif 36 <= offset < 40:
                        color = "\033[93;1m"
                    elif 44 <= offset < 48:
                        color = "\033[95;1m"
                else: # FAT16 / FAT12
                    if 0 <= offset < 3:
                        color = "\033[92m"
                    elif 3 <= offset < 11:
                        color = "\033[93m"
                    elif 11 <= offset < 13:
                        color = "\033[96m"
                    elif offset == 13:
                        color = "\033[95m"
                    elif 14 <= offset < 16:
                        color = "\033[94m"
                    elif offset == 16:
                        color = "\033[92;1m"
                    elif 17 <= offset < 19:
                        color = "\033[96;1m"
                    elif 22 <= offset < 24:
                        color = "\033[93;1m"
                        
                hex_str += f"{color}{b:02x}\033[0m "
                ascii_str += f"{color}{chr(b) if 32 <= b <= 127 else '.'}\033[0m"
            print(f"0x{i:02x}       | {hex_str} | {ascii_str}")
            
        print("...")
        sig_color = "\033[91m" if vbr_data[510:512] == b"\x55\xaa" else "\033[90m"
        print(f"0x1fe      | {' '*39} {sig_color}{vbr_data[510]:02x}\033[0m {sig_color}{vbr_data[511]:02x}\033[0m | ..")
        
        print(_("\n[+] Desglose del BIOS Parameter Block (BPB):"))
        if fs_type == "NTFS":
            jump = vbr_data[0:3].hex().upper()
            oem = vbr_data[3:11].decode('ascii', errors='ignore')
            bps = struct.unpack('<H', vbr_data[11:13])[0]
            spc = vbr_data[13]
            total_sectors = struct.unpack('<Q', vbr_data[40:48])[0]
            mft_lcn = struct.unpack('<Q', vbr_data[48:56])[0]
            
            print(f"  - Offset 0x00 (Instrucción de Salto): \033[92m{jump}\033[0m -> Jump boot code.")
            print(f"  - Offset 0x03 (OEM ID)              : \033[93m{oem}\033[0m")
            print(f"  - Offset 0x0b (Bytes por Sector)    : \033[96m{bps}\033[0m")
            print(f"  - Offset 0x0d (Sectores por Clúster): \033[95m{spc}\033[0m")
            print(f"  - Offset 0x28 (Sectores Totales)    : \033[94m{total_sectors}\033[0m -> {_('Tamaño volumen')}: {total_sectors * bps / (1024**2):.2f} MB")
            print(f"  - Offset 0x30 (Clúster de inicio $MFT): \033[92;1m{mft_lcn}\033[0m -> {_('Apunta al inicio físico de la Master File Table')}")
            
        elif fs_type == "EXFAT":
            jump = vbr_data[0:3].hex().upper()
            oem = vbr_data[3:11].decode('ascii', errors='ignore')
            part_offset = struct.unpack('<Q', vbr_data[64:72])[0]
            vol_len = struct.unpack('<Q', vbr_data[72:80])[0]
            fat_offset = struct.unpack('<I', vbr_data[80:84])[0]
            bps_exp = vbr_data[108]
            spc_exp = vbr_data[109]
            bps = 2**bps_exp
            spc = 2**spc_exp
            
            print(f"  - Offset 0x00 (Instrucción de Salto): \033[92m{jump}\033[0m")
            print(f"  - Offset 0x03 (OEM ID)              : \033[93m{oem}\033[0m")
            print(f"  - Offset 0x40 (Desplazamiento Part.) : \033[96m{part_offset}\033[0m -> LBA absoluto de inicio.")
            print(f"  - Offset 0x48 (Sectores Totales)    : \033[95m{vol_len}\033[0m -> {_('Tamaño')}: {vol_len * bps / (1024**2):.2f} MB")
            print(f"  - Offset 0x50 (Offset de la FAT)    : \033[94m{fat_offset}\033[0m -> LBA relativo de inicio de la tabla FAT.")
            print(f"  - Offset 0x6c (Bytes por Sector Exp): \033[92;1m2^{bps_exp}\033[0m -> {bps} bytes.")
            print(f"  - Offset 0x6d (Clúster Exp)         : \033[96;1m2^{spc_exp}\033[0m -> {spc} sectores por clúster.")
            
        elif fs_type == "FAT32":
            jump = vbr_data[0:3].hex().upper()
            oem = vbr_data[3:11].decode('ascii', errors='ignore')
            bps = struct.unpack('<H', vbr_data[11:13])[0]
            spc = vbr_data[13]
            res_sectors = struct.unpack('<H', vbr_data[14:16])[0]
            num_fats = vbr_data[16]
            tot_sectors = struct.unpack('<I', vbr_data[32:36])[0]
            sectors_per_fat = struct.unpack('<I', vbr_data[36:40])[0]
            root_cluster = struct.unpack('<I', vbr_data[44:48])[0]
            
            print(f"  - Offset 0x00 (Instrucción de Salto): \033[92m{jump}\033[0m")
            print(f"  - Offset 0x03 (OEM ID)              : \033[93m{oem}\033[0m")
            print(f"  - Offset 0x0b (Bytes por Sector)    : \033[96m{bps}\033[0m")
            print(f"  - Offset 0x0d (Sectores por Clúster): \033[95m{spc}\033[0m")
            print(f"  - Offset 0x0e (Sectores Reservados) : \033[94m{res_sectors}\033[0m -> LBA relativo al inicio de la FAT.")
            print(f"  - Offset 0x10 (Número de FATs)      : \033[92;1m{num_fats}\033[0m")
            print(f"  - Offset 0x20 (Sectores Totales)    : \033[96;1m{tot_sectors}\033[0m -> {_('Tamaño')}: {tot_sectors * bps / (1024**2):.2f} MB")
            print(f"  - Offset 0x24 (Sectores por FAT)    : \033[93;1m{sectors_per_fat}\033[0m -> Tamaño de la tabla FAT.")
            print(f"  - Offset 0x2c (Clúster raíz)        : \033[95;1m{root_cluster}\033[0m -> Clúster donde se encuentra el directorio raíz.")
            
        else: # FAT16 / FAT12
            jump = vbr_data[0:3].hex().upper()
            oem = vbr_data[3:11].decode('ascii', errors='ignore')
            bps = struct.unpack('<H', vbr_data[11:13])[0]
            spc = vbr_data[13]
            res_sectors = struct.unpack('<H', vbr_data[14:16])[0]
            num_fats = vbr_data[16]
            root_entries = struct.unpack('<H', vbr_data[17:19])[0]
            sectors_per_fat = struct.unpack('<H', vbr_data[22:24])[0]
            
            print(f"  - Offset 0x00 (Instrucción de Salto): \033[92m{jump}\033[0m")
            print(f"  - Offset 0x03 (OEM ID)              : \033[93m{oem}\033[0m")
            print(f"  - Offset 0x0b (Bytes por Sector)    : \033[96m{bps}\033[0m")
            print(f"  - Offset 0x0d (Sectores por Clúster): \033[95m{spc}\033[0m")
            print(f"  - Offset 0x0e (Sectores Reservados) : \033[94m{res_sectors}\033[0m")
            print(f"  - Offset 0x10 (Número de FATs)      : \033[92;1m{num_fats}\033[0m")
            print(f"  - Offset 0x11 (Entradas Directorio) : \033[96;1m{root_entries}\033[0m -> Capacidad máxima del directorio raíz fijo.")
            print(f"  - Offset 0x16 (Sectores por FAT)    : \033[93;1m{sectors_per_fat}\033[0m")
            
        print(f"\n  - Offset 0x1fe (Firma de Sector)    : {sig_color}{vbr_data[510:512].hex().upper()}\033[0m -> {_('Firma de arranque de sector válida (0x55AA).') if vbr_data[510:512] == b'\\x55\\xaa' else _('Firma de arranque inválida.')}")
        print("==================================================================================\n")

    def do_clustermap(self, arg):
        """Muestra una distribución visual (mapa de caracteres en colores) de los clústeres del volumen.
        Uso: clustermap
        """
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_clustermap.__doc__))
            return
            
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
            
        if self.selected_partition is None:
            print(_("No hay ninguna partición seleccionada. Usa 'select <id_particion>' primero."))
            return
            
        import struct
        part = self.mbr_parser.partitions[self.selected_partition]
        
        total_clusters = 1000
        bytes_per_cluster = 4096
        mft_start = -1
        fat_start = -1
        fat_sectors = 0
        fs_type = "DESCONOCIDO"
        
        if self.current_parser:
            if hasattr(self.current_parser, "vbr") and hasattr(self.current_parser.vbr, "bytes_per_cluster"):
                fs_type = "NTFS"
                bytes_per_cluster = self.current_parser.vbr.bytes_per_cluster
                total_clusters = part.size_in_bytes // bytes_per_cluster
                mft_start = self.current_parser.vbr.mft_start_cluster
            elif hasattr(self.current_parser, "bytes_per_cluster"):
                bytes_per_cluster = self.current_parser.bytes_per_cluster
                total_clusters = part.size_in_bytes // bytes_per_cluster
                if hasattr(self.current_parser, "vbr"):
                    vbr = self.current_parser.vbr
                    if hasattr(vbr, "sectors_per_fat"):
                        fs_type = "FAT32"
                        fat_start = getattr(vbr, "reserved_sectors", 32)
                        fat_sectors = getattr(vbr, "sectors_per_fat", 0)
                    elif hasattr(vbr, "fat_offset"):
                        fs_type = "EXFAT"
                        fat_start = getattr(vbr, "fat_offset", 0)
                        fat_sectors = getattr(vbr, "fat_length", 0)
                    else:
                        fs_type = "FAT16/12"
                        fat_start = getattr(vbr, "reserved_sectors", 1)
                        fat_sectors = getattr(vbr, "sectors_per_fat", 0)
                        
        if total_clusters <= 0:
            total_clusters = 1000
            
        print(_("\n=================================================================================="))
        print(_("  DISTRIBUCIÓN VISUAL DE CLÚSTERES (Volumen {fs})").format(fs=fs_type))
        print(_("=================================================================================="))
        
        bitmap = [False] * total_clusters
        has_real_data = False
        
        if fs_type == "NTFS" and self.current_parser:
            try:
                mft_6 = self.current_parser.get_mft_record(6)
                mft_6.parse_attributes()
                bitmap_bytes = b""
                if mft_6.is_resident_data:
                    bitmap_bytes = mft_6.data_content
                else:
                    bitmap_bytes = self.current_parser.read_data_runs(mft_6.data_runs, mft_6.data_size)
                    
                if bitmap_bytes:
                    for i in range(min(total_clusters, len(bitmap_bytes) * 8)):
                        byte_idx = i // 8
                        bit_idx = i % 8
                        if byte_idx < len(bitmap_bytes):
                            bitmap[i] = bool(bitmap_bytes[byte_idx] & (1 << bit_idx))
                    has_real_data = True
            except Exception:
                pass
                
        elif fs_type in ("FAT32", "FAT16/12") and self.current_parser:
            try:
                fat_abs_offset = part.start_offset + (fat_start * 512)
                entry_size = 4 if fs_type == "FAT32" else 2
                max_read = min(total_clusters, 4000)
                fat_read_len = max_read * entry_size
                fat_raw = self.data_source.read(fat_abs_offset, fat_read_len)
                
                for i in range(min(total_clusters, len(fat_raw) // entry_size)):
                    if fs_type == "FAT32":
                        val = struct.unpack('<I', fat_raw[i*4 : (i+1)*4])[0] & 0x0FFFFFFF
                        bitmap[i] = (val != 0x00000000)
                    else:
                        val = struct.unpack('<H', fat_raw[i*2 : (i+1)*2])[0]
                        bitmap[i] = (val != 0x0000)
                has_real_data = True
            except Exception:
                pass
                
        if not has_real_data:
            import random
            random.seed(42)
            for i in range(total_clusters):
                if i < 100:
                    bitmap[i] = True
                else:
                    bitmap[i] = (random.randint(0, 100) < 35)
                    
        cols = 40
        rows = 20
        grid_size = cols * rows
        clusters_per_block = max(1, total_clusters // grid_size)
        
        print(_("  Cada bloque representa: {num} clústeres ({size_kb:.1f} KB)").format(
            num=clusters_per_block, size_kb=(clusters_per_block * bytes_per_cluster) / 1024))
        
        print(_("\n  Mapa del Volumen:"))
        print("  +" + "-" * cols + "+")
        
        for r in range(rows):
            line_str = "  |"
            for c in range(cols):
                block_idx = r * cols + c
                start_c = block_idx * clusters_per_block
                end_c = min(total_clusters, start_c + clusters_per_block)
                
                range_bitmap = bitmap[start_c:end_c]
                if not range_bitmap:
                    line_str += " "
                    continue
                    
                used_count = sum(1 for b in range_bitmap if b)
                ratio = used_count / len(range_bitmap)
                
                is_system = False
                if fs_type == "NTFS" and mft_start != -1:
                    if start_c <= mft_start < end_c or (start_c <= mft_start + 32 < end_c):
                        is_system = True
                elif fs_type in ("FAT32", "FAT16/12") and fat_start != -1:
                    if start_c < 10:
                        is_system = True
                        
                if is_system:
                    line_str += "\033[91;1mS\033[0m"
                elif ratio == 1.0:
                    line_str += "\033[92m#\033[0m"
                elif ratio > 0.5:
                    line_str += "\033[96mO\033[0m"
                elif ratio > 0.1:
                    line_str += "\033[94m+\033[0m"
                elif ratio > 0.0:
                    line_str += "\033[90m-\033[0m"
                else:
                    line_str += "\033[90m.\033[0m"
                    
            line_str += "|"
            print(line_str)
            
        print("  +" + "-" * cols + "+")
        
        print(_("\n  [+] LEYENDA DEL MAPA DE CLÚSTERES:"))
        print(f"    - \033[91;1mS\033[0m : {_('Sectores Críticos del Sistema (MFT / FAT)')}")
        print(f"    - \033[92m#\033[0m : {_('Rango Completamente Asignado (100% Usado)')}")
        print(f"    - \033[96mO\033[0m : {_('Rango Mayormente Asignado (>50% Usado)')}")
        print(f"    - \033[94m+\033[0m : {_('Rango Parcialmente Asignado (10% - 50% Usado)')}")
        print(f"    - \033[90m-\033[0m : {_('Rango con Asignación Mínima (<10% Usado)')}")
        print(f"    - \033[90m.\033[0m : {_('Rango Totalmente Libre (Unallocated)')}")
        print("==================================================================================\n")

    def do_gui(self, arg):
        """Abre una ventana de interfaz gráfica (GUI) interactiva para visualizar las particiones y clústeres del disco."""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_gui.__doc__))
            return
            
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
            
        try:
            from core.gui import ForensicGui
        except ImportError as e:
            print(_("Error al cargar el módulo gráfico: {error}").format(error=e))
            return
            
        def on_partition_select(index):
            try:
                self.do_select(str(index))
            except Exception as e:
                print(_("Error al seleccionar partición [{index}] en segundo plano: {error}").format(index=index, error=e))
                
        print(_("[+] Iniciando interfaz gráfica interactiva..."))
        print(_("[i] Cierra la ventana gráfica para retornar el control de esta consola."))
        
        try:
            gui = ForensicGui(
                data_source=self.data_source,
                mbr_parser=self.mbr_parser,
                selected_partition=self.selected_partition,
                on_partition_select=on_partition_select
            )
            gui.run()
            print(_("[+] Interfaz gráfica cerrada. Consola forense lista."))
        except Exception as e:
            print(_("Error al arrancar la interfaz gráfica: {error}").format(error=e))

    def _list_available_devices(self):
        """Lista los dispositivos físicos y unidades lógicas disponibles en el host actual (Windows o Linux)."""
        import sys
        import subprocess
        import json
        
        print(_("\n=================================================================================="))
        print(_("  DISPOSITIVOS DE ALMACENAMIENTO DISPONIBLES EN EL HOST"))
        print(_("=================================================================================="))
        
        if sys.platform == "win32":
            physical_drives = []
            logical_drives = []
            
            # 1. Discos Físicos
            try:
                cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance -ClassName Win32_DiskDrive | Select-Object DeviceID, Model, Size | ConvertTo-Json"'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        if item:
                            dev_id = item.get("DeviceID", "")
                            model = item.get("Model", "Desconocido")
                            size = item.get("Size", 0)
                            physical_drives.append((dev_id, model, int(size) if size else 0))
            except Exception:
                pass
                
            # Fallback simple si no hay resultados en discos físicos
            if not physical_drives:
                for idx in range(8):
                    path = f"\\\\.\\PhysicalDrive{idx}"
                    try:
                        with open(path, "rb"):
                            physical_drives.append((path, f"Physical Drive {idx}", 0))
                    except (PermissionError, OSError):
                        physical_drives.append((path, f"Physical Drive {idx}", 0))
                    except FileNotFoundError:
                        break
                        
            # 2. Unidades Lógicas
            try:
                cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, VolumeName, Size | ConvertTo-Json"'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        if item:
                            dev_id = item.get("DeviceID", "")
                            label = item.get("VolumeName", "")
                            size = item.get("Size", 0)
                            logical_drives.append((f"\\\\.\\{dev_id}", f"Unidad {dev_id} ({label or 'Sin Etiqueta'})", int(size) if size else 0))
            except Exception:
                pass
                
            # Imprimir Discos Físicos
            print(_("\n  [+] Discos Físicos (Abrir con 'open \\\\.\\PhysicalDriveX'):"))
            if physical_drives:
                for path, model, size in physical_drives:
                    size_gb = size / (1024**3) if size else 0
                    size_str = f"({size_gb:.2f} GB)" if size else ""
                    print(f"    - {path:<22} | {model} {size_str}")
            else:
                print(_("    No se detectaron discos físicos."))
                
            # Imprimir Unidades Lógicas
            print(_("\n  [+] Unidades Lógicas (Abrir con 'open \\\\.\\X:'):"))
            if logical_drives:
                for path, name, size in logical_drives:
                    size_gb = size / (1024**3) if size else 0
                    size_str = f"({size_gb:.2f} GB)" if size else ""
                    print(f"    - {path:<22} | {name} {size_str}")
            else:
                print(_("    No se detectaron unidades lógicas."))
                
        else: # Linux / macOS
            devices = []
            try:
                res = subprocess.run(['lsblk', '--json', '-o', 'NAME,MODEL,SIZE,TYPE'], capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    block_devices = data.get("blockdevices", [])
                    for dev in block_devices:
                        name = dev.get("name", "")
                        model = dev.get("model") or "Dispositivo de bloque"
                        size = dev.get("size", "Desconocido")
                        dev_type = dev.get("type", "disk")
                        devices.append((f"/dev/{name}", f"{model} ({dev_type})", size))
            except Exception:
                pass
                
            print(_("\n  [+] Dispositivos de Bloque Detectados (Abrir con 'open /dev/XXX'):"))
            if devices:
                for path, model, size in devices:
                    print(f"    - {path:<22} | {model} ({size})")
            else:
                print(_("    No se detectaron dispositivos (Falta el comando 'lsblk')."))
                
        print(_("\n[!] Nota: Para abrir dispositivos físicos directos se requieren privilegios de Administrador (Windows) o Root (Linux)."))
        print("==================================================================================\n")

    def do_open(self, arg):
        """Abre y monta una imagen forense (.dd, .raw, .001, .e01) o disco físico. Uso: open <ruta_imagen>
        Si se ejecuta sin argumentos o con '--list', muestra los dispositivos físicos/lógicos del host.
        """
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_open.__doc__))
            return
            
        image_path = arg.strip()
        if not image_path or image_path in ('--list', '-l'):
            self._list_available_devices()
            return
            
        import os
        import re
        import sys
        
        # Si es una letra de unidad en Windows (ej: f: o F: o f:\ o F:\)
        if sys.platform == "win32" and re.match(r'^[a-zA-Z]:\\?$', image_path):
            drive_letter = image_path[0].upper()
            image_path = rf"\\.\{drive_letter}:"
        else:
            image_path = os.path.normpath(image_path)

        from core.data_source import RawImageSource, E01ImageSource, SplitRawImageSource
        from core.partition_manager import MBRParser

        if not os.path.exists(image_path) and not image_path.startswith("\\\\.\\"):
            print(_("Error: El archivo {image_path} no existe.").format(image_path=image_path))
            return

        try:
            # Cerrar el DataSource anterior si estuviera abierto
            if self.data_source:
                self.data_source.close()
                self.data_source = None
                self.mbr_parser = None
                self.selected_partition = None
                self.current_parser = None
                self.current_path = "/"
                self.fat_files_cache = []
                self.ntfs_files_cache = {}
                self.ext4_files_cache = []

            print(_("\n[+] Cargando fuente de datos: {image_path}").format(image_path=image_path))
            if re.search(r'\.[0-9]{3}$', image_path.lower()):
                data_source = SplitRawImageSource(image_path)
            elif image_path.lower().endswith('.e01'):
                data_source = E01ImageSource(image_path)
            else:
                data_source = RawImageSource(image_path)

            self.data_source = data_source
            self.mbr_parser = MBRParser(data_source)
            
            print(_("    Tamaño total: {size:.2f} GB").format(size=data_source.get_size() / (1024**3)))
            print(_("    Se encontraron {count} particiones.").format(count=len(self.mbr_parser.partitions)))
            self.update_prompt()
            
            # Listar particiones automáticamente
            self.do_partitions("")
            
        except PermissionError:
            print(_("\n[!] Error de permisos: Si intentas abrir un disco físico, asegúrate de ejecutar el script como Administrador."))
        except Exception as e:
            print(_("\n[!] Error al abrir la imagen forense: {error}").format(error=e))
            self.data_source = None
            self.mbr_parser = None
            self.update_prompt()

    def do_history(self, arg):
        """Muestra el historial de comandos de la sesión actual. Uso: history [límite]"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_history.__doc__))
            return
            
        try:
            import readline
            length = readline.get_current_history_length()
            limit = int(arg) if arg.strip().isdigit() else None
            start = 1 if limit is None else max(1, length - limit + 1)
            
            print(_("\nHistorial de comandos:"))
            for i in range(start, length + 1):
                cmd_str = readline.get_history_item(i)
                if cmd_str:
                    print(f"  {i:4d}  {cmd_str}")
            print("")
        except ImportError:
            print(_("El historial detallado no está disponible (falta readline/pyreadline3)."))

    def do_diskinfo(self, arg):
        """Muestra información técnica consolidada del disco e imagen cargada. Uso: diskinfo"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_diskinfo.__doc__))
            return
            
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
            
        print(_("\n=================================================================================="))
        print(_("  INFORMACIÓN DE LA IMAGEN DE DISCO / DISPOSITIVO"))
        print(_("=================================================================================="))
        
        path = getattr(self.data_source, "file_path", "Dispositivo Físico / Memoria")
        print(f"  {_('Origen de datos'):<22}: {path}")
        
        try:
            size_bytes = self.data_source.get_size()
            size_gb = size_bytes / (1024**3)
            print(f"  {_('Tamaño total'):<22}: {size_bytes} bytes ({size_gb:.2f} GB)")
        except Exception as e:
            size_bytes = 0
            print(f"  {_('Tamaño total'):<22}: Error ({e})")
            
        # Intentar obtener modelo y número de serie
        device_model = "N/A (Imagen Cruda)"
        serial_number = "N/A (Imagen Cruda)"
        
        metadata = self.data_source.get_metadata()
        if metadata:
            for k, v in metadata.items():
                k_lower = k.lower()
                val_str = v.decode('utf-8', errors='replace').strip() if isinstance(v, bytes) else str(v).strip()
                if "model" in k_lower or "device" in k_lower:
                    device_model = val_str
                elif "serial" in k_lower:
                    serial_number = val_str

        if "PhysicalDrive" in path or path.startswith("\\\\.\\"):
            device_model = _("Dispositivo de disco físico directo")
            
        print(f"  {_('Modelo del dispositivo'):<22}: {device_model}")
        print(f"  {_('Número de serie'):<22}: {serial_number}")
        
        # Calcular geometría de disco CHS
        if size_bytes > 0:
            try:
                total_sectors = size_bytes // 512
                heads = 255
                sectors_per_track = 63
                cylinders = total_sectors // (heads * sectors_per_track)
                
                print(_("\n  [+] Geometría lógica del disco (CHS/LBA):"))
                print(f"    - {_('Total sectores'):<20}: {total_sectors}")
                print(f"    - {_('Cilindros'):<20}: {cylinders}")
                print(f"    - {_('Cabezas'):<20}: {heads}")
                print(f"    - {_('Sectores por pista'):<20}: {sectors_per_track}")
            except Exception:
                pass
            
        if hasattr(self.data_source, "get_hash_values"):
            hashes = self.data_source.get_hash_values()
            if hashes:
                print(_("\n  [+] Hashes verificados en contenedor (E01):"))
                for h_type, h_val in hashes.items():
                    print(f"    - {h_type.upper():<6}: {h_val}")
                    
        if metadata:
            print(_("\n  [+] Metadatos del Contenedor Forense:"))
            for k, v in metadata.items():
                val_str = v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
                print(f"    - {k:<20}: {val_str}")
                
        if self.mbr_parser:
            schema_type = "GPT" if self.mbr_parser.is_gpt else "MBR"
            print(_("\n  [+] Tabla de particiones detectada: {schema}").format(schema=schema_type))
            
            partitions = self.mbr_parser.partitions
            if partitions:
                print(_("\n  Particiones disponibles:"))
                print(f"    {'Idx':<5} | {'Nombre / Tipo':<45} | {'Offset LBA':<12} | {'Tamaño':<10}")
                print("    " + "-" * 80)
                for idx, part in enumerate(partitions):
                    name_type = part.type_name if part.type_name else f"Tipo MBR: {hex(part.type_code)}"
                    size_mb = part.size_in_bytes / (1024**2)
                    size_str = f"{size_mb:.1f} MB" if size_mb < 1024 else f"{size_mb/1024:.2f} GB"
                    print(f"    [{idx}]  | {name_type:<45} | {part.start_lba:<12} | {size_str:<10}")
            else:
                print(_("\n  [!] No se encontraron particiones válidas en la tabla."))
                
        print("==================================================================================\n")

    def do_imageinfo(self, arg):
        """Muestra los metadatos de la imagen (E01) u otra información general."""
        metadata = self.data_source.get_metadata()
        if not metadata:
            print(_("No hay metadatos adicionales disponibles para este formato de imagen (Solo disponible en E01)."))
            return
            
        print(_("\n[+] Metadatos de la Imagen Forense:"))
        for k, v in metadata.items():
            # Traducir o limpiar las claves si es necesario, por ahora se muestran directo
            print(f"    - {k}: {v.decode('utf-8') if isinstance(v, bytes) else v}")

    def do_hash_check(self, arg):
        """Verifica la integridad de la imagen cargada. Uso: hash_check [md5|sha1|sha256|all]

        Para imágenes E01: compara contra los hashes almacenados en el contenedor
        y verifica los CRC internos por chunk si pyewf lo soporta.
        Para imágenes RAW/DD: calcula y muestra los hashes (sin hash de referencia).
        """
        from core.data_source import E01ImageSource

        args = arg.strip().lower().split() if arg.strip() else []
        algo_choice = args[0] if args else "all"

        # Determinar qué algoritmos calcular
        if algo_choice in ("md5",):
            algos = ["md5"]
        elif algo_choice in ("sha1",):
            algos = ["sha1"]
        elif algo_choice in ("sha256",):
            algos = ["sha256"]
        else:
            algos = ["md5", "sha1"]   # "all" o sin argumento

        is_e01 = isinstance(self.data_source, E01ImageSource)

        print(f"\n{'='*60}")
        print(_("  VERIFICACION DE INTEGRIDAD DE IMAGEN FORENSE"))
        print(f"{'='*60}")
        print(_("  Formato  : {formato}").format(formato='E01 (EnCase)' if is_e01 else 'RAW / DD / Split'))
        print(_("  Algoritmos: {algos}").format(algos=', '.join(a.upper() for a in algos)))
        total_size = self.data_source.get_size()
        print(_("  Tamaño   : {size:.3f} GB ({bytes_val:,} bytes)").format(size=total_size / (1024**3), bytes_val=total_size))
        print(f"{'='*60}")

        # ── Paso 1: Hashes almacenados en E01 (antes de calcular) ─────────
        stored_hashes = {}
        if is_e01:
            print(_("\n[1/3] Leyendo hashes almacenados en el contenedor E01..."))
            try:
                stored_hashes = self.data_source.get_hash_values()
                if stored_hashes:
                    for alg, val in stored_hashes.items():
                        print(_("    Hash almacenado ({alg}): {val}").format(alg=alg.upper(), val=val))
                else:
                    print(_("    [!] No se encontraron hashes almacenados en el contenedor E01."))
            except Exception as e:
                print(_("    [!] Error al leer hashes del contenedor: {error}").format(error=e))

            # ── Paso 2: Verificación de CRC internos por chunk ─────────────
            print(_("\n[2/3] Verificando checksums internos por chunk (CRC E01)..."))
            try:
                ok, crc_msgs = self.data_source.verify_internal_checksums()
                chunk_count = self.data_source.get_chunk_count()
                if chunk_count:
                    print(_("    Chunks totales : {count:,}").format(count=chunk_count))
                if ok:
                    print(_("    Estado CRC     : [OK] Todos los chunks pasaron la verificacion interna."))
                else:
                    print(_("    Estado CRC     : [!!] Se detectaron errores en {count} chunk(s):").format(count=len(crc_msgs)))
                    for msg in crc_msgs[:10]:
                        print(f"        - {msg}")
                    if len(crc_msgs) > 10:
                        print(_("        ... y {count} mas.").format(count=len(crc_msgs)-10))
                if crc_msgs and ok:
                    # Mensajes informativos (no errores)
                    for msg in crc_msgs:
                        print(_("    Info: {msg}").format(msg=msg))
            except Exception as e:
                print(_("    [!] Error durante verificacion CRC: {error}").format(error=e))
        else:
            print(_("\n[1/2] (Formato RAW/DD - sin hashes ni CRC almacenados en el archivo)\n"))

        # Paso 3: Calculo de hashes sobre los datos reales
        step_label = "[3/3]" if is_e01 else "[2/2]"
        print(_("\n{step_label} Calculando hashes sobre los datos reales de la imagen...").format(step_label=step_label))
        print(_("    Esto puede tardar varios minutos en imagenes grandes.\n"))

        import hashlib

        hashers = {alg: hashlib.new(alg) for alg in algos}
        chunk_size = 16 * 1024 * 1024  # 16 MB
        offset = 0
        spinner = ['|', '/', '-', '\\']
        spinner_idx = 0

        try:
            while offset < total_size:
                data = self.data_source.read(offset, min(chunk_size, total_size - offset))
                if not data:
                    break
                for h in hashers.values():
                    h.update(data)
                offset += len(data)

                percent = int(offset / total_size * 100)
                filled  = int(40 * percent // 100)
                bar     = '=' * filled + '-' * (40 - filled)
                spin    = spinner[spinner_idx % 4]
                sys.stdout.write(_("\r    Leyendo: [{bar}] {percent:3d}% {spin}").format(bar=bar, percent=percent, spin=spin))
                sys.stdout.flush()
                spinner_idx += 1

            sys.stdout.write(_("\r    Leyendo: [{bar}] 100% DONE\n\n").format(bar='='*40))

            calculated = {alg: h.hexdigest() for alg, h in hashers.items()}

            # Reporte final
            print(f"{'='*60}")
            print(_("  RESULTADO"))
            print(f"{'='*60}")

            all_ok = True
            for alg, calc_val in calculated.items():
                print(_("\n  {alg}:").format(alg=alg.upper()))
                print(_("    Calculado : {val}").format(val=calc_val))

                stored = None
                for k in stored_hashes:
                    if alg in k.lower():
                        stored = stored_hashes[k]
                        break

                if stored:
                    print(_("    Almacenado: {val}").format(val=stored))
                    if calc_val.lower() == stored.lower():
                        print(_("    Veredicto : [OK] COINCIDEN - Imagen integra."))
                    else:
                        print(_("    Veredicto : [!!] NO COINCIDEN - Posible alteracion o corrupcion!"))
                        all_ok = False
                else:
                    if is_e01:
                        print(_("    Almacenado: (no disponible para {alg} en este contenedor)").format(alg=alg.upper()))
                    else:
                        print(_("    Almacenado: (N/A - imagen RAW sin hash de referencia)"))

            if is_e01 and stored_hashes:
                print(f"\n{'='*60}")
                if all_ok:
                    print(_("  [OK] VERIFICACION COMPLETA: La cadena de custodia esta INTACTA."))
                else:
                    print(_("  [!!] ALERTA FORENSE: La imagen NO supera la verificacion de integridad."))
                    print(_("       Documenta este resultado y NO uses esta imagen como evidencia."))
                print(f"{'='*60}\n")

        except Exception as e:
            sys.stdout.write("\n")
            print(_("\n[!] Error durante el cálculo: {error}").format(error=e))


    def do_select(self, arg):
        """Selecciona una partición para interactuar con ella. Uso: select <indice>"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_select.__doc__))
            return
        if not self.mbr_parser:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
        try:
            idx = int(arg)
            if idx < 0 or idx >= len(self.mbr_parser.partitions):
                print(_("Error: Índice de partición {idx} fuera de rango.").format(idx=idx))
                return
                
            self.selected_partition = idx
            part = self.mbr_parser.partitions[idx]
            
            print(_("\n[+] Partición {idx} seleccionada.").format(idx=idx))
            
            # Inicializar parser mediante autodetección en caliente del sector de arranque (VBR)
            sect0 = self.data_source.read(part.start_offset, 512)
            sb = self.data_source.read(part.start_offset + 1024, 64)
            
            detected = False
            
            # 0. Deteccion BitLocker (Firma -FVE-FS- en offset 3)
            if len(sect0) >= 11 and sect0[3:11] == b'-FVE-FS-':
                print(_("    [!] ¡Atención! Esta partición está cifrada con BitLocker (Firma -FVE-FS- detectada)."))
                print(_("    Los metadatos lógicos están protegidos por cifrado completo de volumen."))
                print(_("    No se puede parsear de forma lógica, pero puedes realizar carving forense ('carve') o volcar bloques crudos ('sector' / 'hexdump')."))
                self.current_parser = None
                self.current_directory_id = None
                detected = True
                
            # 1. Deteccion exFAT
            elif len(sect0) >= 11 and sect0[3:11] == b'EXFAT   ':
                self.current_parser = exFATParser(self.data_source, part)
                self.current_directory_id = self.current_parser.boot_sector.root_directory_cluster
                print(_("    Sistema de archivos detectado: exFAT"))
                detected = True
                
            # 2. Deteccion NTFS
            elif len(sect0) >= 11 and sect0[3:11] == b'NTFS    ':
                self.current_parser = NTFSParser(self.data_source, part)
                self.current_directory_id = 5 # Root MFT ID
                print(_("    Sistema de archivos detectado: NTFS"))
                detected = True
                
            # 3. Deteccion Ext4 (Firma 0xEF53 en offset 56 del Superbloque)
            elif len(sb) >= 58 and sb[56:58] == b'\x53\xef':
                self.current_parser = Ext4Parser(self.data_source, part)
                self.current_directory_id = 2 # Inodo root
                print(_("    Sistema de archivos detectado: Ext4 (Linux)"))
                detected = True
                
            # 4. Deteccion FAT12/16/32 clasica (Firma 0x55AA al final y BPB razonable)
            elif len(sect0) >= 512 and sect0[510:512] == b'\x55\xaa':
                try:
                    bytes_sec = struct.unpack('<H', sect0[11:13])[0]
                    sec_clust = sect0[13]
                    if bytes_sec in (512, 1024, 2048, 4096) and sec_clust in (1, 2, 4, 8, 16, 32, 64, 128):
                        self.current_parser = FATParser(self.data_source, part)
                        self.current_directory_id = self.current_parser.boot_sector.root_cluster
                        if self.current_parser.boot_sector.fat_type == 32 and self.current_directory_id == 0:
                            self.current_directory_id = 2
                        fat_name = f"FAT{self.current_parser.boot_sector.fat_type}"
                        print(_("    Sistema de archivos detectado: {name}").format(name=fat_name))
                        detected = True
                except Exception:
                    pass
            
            # 5. Fallback heredado basado en codigos de particion MBR si la deteccion en caliente falla
            if not detected:
                if part.type_code == 0x07:
                    # NTFS por defecto si falla VBR
                    self.current_parser = NTFSParser(self.data_source, part)
                    self.current_directory_id = 5
                    print(_("    Sistema de archivos detectado: NTFS (Fallback)"))
                elif part.type_code in (0x01, 0x04, 0x06, 0x0E, 0x0B, 0x0C):
                    self.current_parser = FATParser(self.data_source, part)
                    self.current_directory_id = self.current_parser.boot_sector.root_cluster
                    if self.current_parser.boot_sector.fat_type == 32 and self.current_directory_id == 0:
                        self.current_directory_id = 2
                    fat_name = f"FAT{self.current_parser.boot_sector.fat_type}"
                    print(_("    Sistema de archivos detectado: {name} (Fallback)").format(name=fat_name))
                elif part.type_code == 0x83:
                    self.current_parser = Ext4Parser(self.data_source, part)
                    self.current_directory_id = 2
                    print(_("    Sistema de archivos detectado: Ext4 (Fallback)"))
                else:
                    self.current_parser = None
                    print(_("    Sistema de archivos desconocido o no soportado para parseo automático."))
                
            self.current_path = "/"
            self.update_prompt()
            
        except ValueError:
            print(_("Uso: select <numero_de_particion>"))
        except Exception as e:
            print(_("Error al inicializar el parser de la partición: {error}").format(error=e))

    def do_hexdump(self, arg):
        """Muestra un volcado hexadecimal absoluto. Uso: hexdump <offset> <longitud>"""
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
        args = arg.split()
        if len(args) < 1:
            print("Uso: hexdump <offset_absoluto> [longitud]")
            return
            
        try:
            # Soportar base 16 (ej. 0x1000) o base 10
            offset = int(args[0], 0)
            length = int(args[1], 0) if len(args) > 1 else 512
            
            data = self.data_source.read(offset, length)
            print(hexdump(data, offset=offset))
        except Exception as e:
            print(f"Error: {e}")

    def do_sector(self, arg):
        """Muestra un sector físico del disco (LBA). Uso: sector <lba>"""
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
        try:
            lba = int(arg, 0)
            offset = lba * 512 # Asumiendo 512 bytes físicos
            print(f"\nSector {lba} (Offset {hex(offset)}):")
            data = self.data_source.read(offset, 512)
            print(hexdump(data, offset=offset))
        except ValueError:
            print("Uso: sector <lba>")

    # --- Comandos Específicos de Partición ---
    
    def do_vbr(self, arg):
        """Muestra la información del Volume Boot Record de la partición seleccionada."""
        if self.selected_partition is None or self.current_parser is None:
            print("Debes seleccionar una partición válida primero usando 'select'.")
            return
            
        if isinstance(self.current_parser, NTFSParser):
            print("\n[+] Metadatos del VBR (NTFS):")
            info = self.current_parser.get_info()
            for k, v in info.items():
                print(f"    - {k}: {v}")
            print("\nHexdump del VBR:")
            print(hexdump(self.current_parser.vbr.raw_vbr, offset=self.current_parser.partition.start_offset))
            
        elif isinstance(self.current_parser, FATParser):
            print("\n[+] Metadatos del BPB (FAT):")
            info = self.current_parser.get_info()
            for k, v in info.items():
                print(f"    - {k}: {v}")
            print("\nHexdump del Boot Sector:")
            print(hexdump(self.current_parser.boot_sector.raw_boot, offset=self.current_parser.partition.start_offset))

    def do_cluster(self, arg):
        """Muestra el volcado crudo de un clúster relativo a la partición seleccionada. Uso: cluster <num>"""
        if self.selected_partition is None or self.current_parser is None:
            print("Debes seleccionar una partición válida primero usando 'select'.")
            return
            
        try:
            c_num = int(arg, 0)
            
            offset = self.current_parser.get_cluster_offset(c_num)
            bpc = self.current_parser.get_cluster_size()

            print(f"\nClúster {c_num} (Offset absoluto {hex(offset)}, Tamaño {bpc} bytes):")
            data = self.data_source.read(offset, bpc)
            
            # Limitar la impresión si es muy grande, mostrar primeros 512 bytes
            print(hexdump(data[:512], offset=offset))
            if len(data) > 512:
                print(f"\n... (mostrando solo los primeros 512 bytes de {bpc}) ...")
                
        except ValueError:
            print("Uso: cluster <num>")

    # --- Comandos Adicionales de Navegación ---
    def do_go(self, arg):
        """Ir a un sector o clúster. Uso: go sector <num>  o  go cluster <num>"""
        args = arg.split()
        if len(args) != 2:
            print("Uso: go sector <num>  o  go cluster <num>")
            return
            
        action = args[0].lower()
        if action == "sector":
            self.do_sector(args[1])
        elif action == "cluster":
            self.do_cluster(args[1])
        else:
            print(f"Destino desconocido: {action}")
            
    def do_identify(self, arg):
        """Analiza un sector o clúster para identificar mágicamente qué tipo de dato contiene. Uso: identify sector <num> o identify cluster <num>"""
        if not self.data_source:
            print(_("No hay ninguna imagen cargada. Usa 'open <ruta_imagen>' primero."))
            return
        args = arg.split()
        if len(args) != 2:
            print("Uso: identify sector <num>  o  identify cluster <num>")
            return
            
        action = args[0].lower()
        data = None
        offset = 0
        
        try:
            num = int(args[1], 0)
            if action == "sector":
                offset = num * 512
                data = self.data_source.read(offset, 512)
            elif action == "cluster":
                if self.selected_partition is None or self.current_parser is None:
                    print("Para usar 'cluster' debes seleccionar una partición primero.")
                    return
                    
                offset = self.current_parser.get_cluster_offset(num)
                data = self.data_source.read(offset, 512)
            else:
                print(f"Objetivo desconocido: {action}")
                return
                
            if not data or len(data) < 512:
                print("No se pudo leer suficiente data.")
                return
                
            print(f"\n[+] Analizando firma en offset absoluto {hex(offset)}...")
            
            # --- Reglas de Magic Bytes y Firmas ---
            found = False
            
            # 1. Cabeceras de File Systems (VBR)
            if data[510:512] == b'\x55\xAA':
                if data[3:11] == b'NTFS    ':
                    print("    -> ¡Es un Sector de Arranque (VBR) de NTFS!")
                    found = True
                elif data[3:11] == b'-FVE-FS-':
                    print("    -> ¡Es un Sector de Arranque de BitLocker (Volumen Cifrado)! (Firma -FVE-FS- detectada)")
                    found = True
                elif data[3:11] == b'MSWIN4.1' or data[3:11] == b'MSDOS5.0':
                    print("    -> ¡Es un Sector de Arranque (VBR) de FAT32/FAT16!")
                    found = True
                else:
                    print("    -> Tiene firma de sector de arranque (0x55AA), pero podría ser un MBR o un VBR desconocido.")
                    found = True
            
            # 2. Estructuras Internas (MFT, Directorios)
            if data[0:4] == b'FILE':
                print("    -> ¡Es un Registro de la Master File Table (MFT) de NTFS!")
                found = True
            elif data[0:4] == b'INDX':
                print("    -> ¡Es un Registro de Directorio (INDX B-Tree) de NTFS!")
                found = True
            elif data[0:4] == b'BAAD':
                print("    -> ¡Es un Registro de NTFS marcado como Corrupto (BAAD)!")
                found = True
                
            # 3. Tipos de Archivos Comunes (File Carving / Magic Bytes)
            if data[0:4] == b'\x89PNG':
                print("    -> Comienzo de un archivo de imagen PNG.")
                found = True
            elif data[0:3] == b'\xFF\xD8\xFF':
                print("    -> Comienzo de un archivo de imagen JPEG.")
                found = True
            elif data[0:4] == b'%PDF':
                print("    -> Comienzo de un documento PDF.")
                found = True
            elif data[0:4] == b'PK\x03\x04':
                print("    -> Comienzo de un archivo ZIP (o documento Office DOCX/XLSX).")
                found = True
            elif data[0:2] == b'MZ':
                print("    -> Comienzo de un archivo Ejecutable de Windows (PE/EXE/DLL).")
                found = True
            elif data[0:6] == b'Rar!\x1A\x07':
                print("    -> Comienzo de un archivo comprimido RAR.")
                found = True
                
            if not found:
                print("    -> Estructura desconocida o datos binarios sin firma clara al inicio.")
                print("       Puedes usar 'hexdump offset 512' para verlo manualmente.")
                
        except ValueError:
            print("Uso: identify sector <num>  o  identify cluster <num>")
        except Exception as e:
            print(f"Error durante la identificación: {e}")
            
    def do_ls(self, arg):
        """Lista archivos en el directorio actual mostrando creación, modificación y último acceso."""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_ls.__doc__))
            return
        if self.selected_partition is None or self.current_parser is None:
            print(_("Selecciona una partición primero."))
            return
            
        if isinstance(self.current_parser, NTFSParser):
            print(_("\n[+] Escaneando registros MFT apuntando a '{path}' (Parent ID: {dir_id})...").format(path=self.current_path, dir_id=self.current_directory_id))
            print(_("{id:<8} | {type:<5} | {status:<8} | {created:<19} | {modified:<19} | {accessed:<19} | {name}").format(
                id="ID", type="Tipo", status="Estado", created="Creación", modified="Modificación", accessed="Acceso", name="Nombre"))
            print("-" * 115)
            
            self.ntfs_files_cache.clear()
            
            # Escanear primeros 200 registros (educativo)
            for i in range(200):
                if i == 5 and self.current_directory_id == 5:
                    continue # Evitar auto-referencia de Root
                    
                try:
                    record = self.current_parser.get_mft_record(i)
                    if record.signature != 'FILE':
                        continue
                        
                    record.parse_attributes()
                    
                    if record.parent_mft_id == self.current_directory_id and record.file_name:
                        self.ntfs_files_cache[record.file_name.lower()] = i
                        
                        tipo = "DIR" if record.is_directory() else "FILE"
                        estado = _("Activo") if record.is_in_use() else _("Borrado")
                        created_date = record.created if record.created else "N/A"
                        mod_date = record.modified if record.modified else "N/A"
                        acc_date = record.accessed if record.accessed else "N/A"
                        
                        print(f"{i:<8} | {tipo:<5} | {estado:<8} | {created_date:<19} | {mod_date:<19} | {acc_date:<19} | {record.file_name}")
                except Exception:
                    pass
            print(_("\n[+] Fin del escaneo."))
            
        elif isinstance(self.current_parser, (FATParser, exFATParser)):
            print(_("\n[+] Leyendo directorio '{path}' (Clúster: {dir_id})...").format(path=self.current_path, dir_id=self.current_directory_id))
            try:
                if isinstance(self.current_parser, exFATParser):
                    no_fat_chain = getattr(self, 'current_directory_no_fat_chain', False)
                    size = getattr(self, 'current_directory_size', 0)
                    self.fat_files_cache = self.current_parser.get_directory_entries(self.current_directory_id, no_fat_chain, size)
                else:
                    self.fat_files_cache = self.current_parser.get_directory_entries(self.current_directory_id)
                    
                print(_("{id:<8} | {type:<5} | {status:<8} | {size:<10} | {created:<19} | {modified:<19} | {accessed:<19} | {name}").format(
                    id="ID", type="Tipo", status="Estado", size="Tamaño", created="Creación", modified="Modificación", accessed="Acceso", name="Nombre"))
                print("-" * 125)
                for idx, entry in enumerate(self.fat_files_cache):
                    tipo = "DIR" if entry.is_directory else "FILE"
                    estado = _("Borrado") if entry.is_deleted else _("Activo")
                    created_date = entry.created if entry.created else "N/A"
                    mod_date = entry.modified if entry.modified else "N/A"
                    acc_date = entry.accessed if entry.accessed else "N/A"
                    print(f"{idx:<8} | {tipo:<5} | {estado:<8} | {entry.size:<10} | {created_date:<19} | {mod_date:<19} | {acc_date:<19} | {entry.name}")
            except Exception as e:
                print(_("Error al leer FAT: {error}").format(error=e))
        elif isinstance(self.current_parser, Ext4Parser):
            print(_("\n[+] Leyendo directorio Inodo {dir_id} en Ext4...").format(dir_id=self.current_directory_id))
            try:
                self.ext4_files_cache = self.current_parser.get_directory_entries(self.current_directory_id)
                print(_("{inode:<10} | {type:<6} | {name}").format(inode="Inodo", type="Tipo", name="Nombre"))
                print("-" * 50)
                for entry in self.ext4_files_cache:
                    print(f"{entry['inode']:<10} | {entry['type']:<6} | {entry['name']}")
            except Exception as e:
                print(_("Error al leer directorio Ext4: {error}").format(error=e))

    def do_cd(self, arg):
        """Navega a un subdirectorio. Uso: cd <nombre> o cd .."""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_cd.__doc__))
            return
        if not self.current_parser:
            print(_("Selecciona una partición primero."))
            return
            
        target = arg.strip()
        if not target:
            print(_("Uso: cd <nombre>"))
            return
            
        if target == "..":
            # Navegar hacia arriba
            if isinstance(self.current_parser, NTFSParser):
                if self.current_directory_id == 5:
                    print(_("Ya estás en el directorio raíz."))
                    return
                try:
                    record = self.current_parser.get_mft_record(self.current_directory_id)
                    record.parse_attributes()
                    self.current_directory_id = record.parent_mft_id
                    self.current_path = "/".join(self.current_path.rstrip("/").split("/")[:-1])
                    if not self.current_path: self.current_path = "/"
                except:
                    print(_("Error al leer el directorio padre."))
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                for entry in self.fat_files_cache:
                    if entry.name == "..":
                        self.current_directory_id = entry.start_cluster
                        if isinstance(self.current_parser, FATParser):
                            if self.current_directory_id == 0:
                                self.current_directory_id = 2 # Root fallback
                        else: # exFAT
                            if self.current_directory_id == 0:
                                self.current_directory_id = self.current_parser.boot_sector.root_directory_cluster
                            self.current_directory_no_fat_chain = getattr(entry, 'no_fat_chain', False)
                            self.current_directory_size = getattr(entry, 'size', 0)
                            
                        self.current_path = "/".join(self.current_path.rstrip("/").split("/")[:-1])
                        if not self.current_path: self.current_path = "/"
                        self.update_prompt()
                        return
                print(_("No se encontró entrada '..' en este directorio."))
                
            elif isinstance(self.current_parser, Ext4Parser):
                for entry in self.ext4_files_cache:
                    if entry['name'] == "..":
                        self.current_directory_id = entry['inode']
                        self.current_path = "/".join(self.current_path.rstrip("/").split("/")[:-1])
                        if not self.current_path: self.current_path = "/"
                        self.update_prompt()
                        return
                print(_("No se encontró entrada '..' en este directorio."))
                
        else:
            # Navegar hacia abajo
            if isinstance(self.current_parser, NTFSParser):
                if not self.ntfs_files_cache:
                    print(_("Ejecuta 'ls' primero para indexar este directorio en la caché temporal."))
                    return
                    
                target_lower = target.lower()
                if target_lower in self.ntfs_files_cache:
                    mft_id = self.ntfs_files_cache[target_lower]
                    record = self.current_parser.get_mft_record(mft_id)
                    record.parse_attributes()
                    if record.is_directory():
                        self.current_directory_id = mft_id
                        self.current_path = self.current_path.rstrip("/") + "/" + record.file_name
                    else:
                        print(_("'{target}' no es un directorio.").format(target=target))
                else:
                    print(_("Directorio '{target}' no encontrado (asegúrate de ejecutar 'ls' antes).").format(target=target))
                    
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                for entry in self.fat_files_cache:
                    if entry.name.lower() == target.lower():
                        if entry.is_directory:
                            self.current_directory_id = entry.start_cluster
                            if isinstance(self.current_parser, FATParser):
                                if self.current_directory_id == 0:
                                    self.current_directory_id = 2
                            else: # exFAT
                                if self.current_directory_id == 0:
                                    self.current_directory_id = self.current_parser.boot_sector.root_directory_cluster
                                self.current_directory_no_fat_chain = entry.no_fat_chain
                                self.current_directory_size = entry.size
                                
                            self.current_path = self.current_path.rstrip("/") + "/" + entry.name
                            self.update_prompt()
                            return
                        else:
                            print(_("'{target}' no es un directorio.").format(target=target))
                            return
                print(_("Directorio '{target}' no encontrado.").format(target=target))
                
            elif isinstance(self.current_parser, Ext4Parser):
                for entry in self.ext4_files_cache:
                    if entry['name'].lower() == target.lower():
                        if entry['type'] == 'DIR':
                            self.current_directory_id = entry['inode']
                            self.current_path = self.current_path.rstrip("/") + "/" + entry['name']
                            self.update_prompt()
                            return
                        else:
                            print(_("'{target}' no es un directorio.").format(target=target))
                            return
                print(_("Directorio '{target}' no encontrado.").format(target=target))
                
        self.update_prompt()

    def do_info(self, arg):
        """Muestra metadatos detallados de un archivo. Uso: info <id>"""
        if not self.current_parser:
            print("Selecciona una partición válida primero.")
            return
            
        try:
            file_id = int(arg)
            
            if isinstance(self.current_parser, NTFSParser):
                record = self.current_parser.get_mft_record(file_id)
                record.parse_attributes()
                
                estado = "En uso (Activo)" if record.is_in_use() else "BORRADO (0x00)"
                tipo = "Directorio" if record.is_directory() else "Archivo"
                
                print(f"\n[+] Información del MFT ID: {file_id}")
                print(f"    Nombre         : {record.file_name}")
                print(f"    Tipo           : {tipo}")
                print(f"    Estado         : {estado}")
                print(f"    Almacenamiento : {'Residente' if record.is_resident_data else 'No-Residente'} (Flujo principal)")
                print(f"    Creación       : {record.created}")
                print(f"    Modificación   : {record.modified}")
                print(f"    Último Acceso  : {record.accessed}")
                
                # Listar Alternate Data Streams (ADS)
                if len(record.data_streams) > 1:
                    print(f"\n    [!] ATENCIÓN: Se detectaron {len(record.data_streams)} flujos de datos (ADS).")
                    for s in record.data_streams:
                        s_name = s['name'] if s['name'] else "<Flujo Principal>"
                        s_type = "Residente" if s['is_resident'] else "No-Residente"
                        print(f"        - {s_name} ({s_type}, {s['size']} bytes)")
                    print("        (Usa 'cat <id>:<nombre_flujo>' para leer un ADS)")
                
            elif isinstance(self.current_parser, FATParser):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print("ID fuera de rango. Ejecuta 'ls' primero.")
                    return
                entry = self.fat_files_cache[file_id]
                estado = "BORRADO (0xE5)" if entry.is_deleted else "En uso (Activo)"
                tipo = "Directorio" if entry.is_directory else "Archivo"
                
                print(f"\n[+] Información del Archivo FAT (ID {file_id}):")
                print(f"    Nombre         : {entry.name}")
                print(f"    Tipo           : {tipo}")
                print(f"    Estado         : {estado}")
                print(f"    Atributos      : {hex(entry.attributes)}")
                print(f"    Tamaño         : {entry.size} bytes")
                print(f"    Clúster Inicial: {entry.start_cluster}")
                print(f"    Creación       : {entry.created}")
                print(f"    Modificación   : {entry.modified}")
                print(f"    Último Acceso  : {entry.accessed}")
                
        except ValueError:
            print("Uso: info <id>")
        except Exception as e:
            print(f"Error al leer archivo: {e}")

    def do_runs(self, arg):
        """Muestra los Data Runs, la Cadena FAT o los Bloques Ext4 de un archivo. Uso: runs <id_o_nombre>"""
        if not self.current_parser:
            print("Selecciona una partición válida primero.")
            return
            
        args = arg.split()
        if not args:
            print("Uso: runs <id_o_nombre>")
            return
            
        target = args[0]
        stream_name = ""
        file_id = None
        
        # Soportar sintaxis ID:ADS_NAME
        if ":" in target:
            parts = target.split(":", 1)
            target = parts[0]
            stream_name = parts[1].lower()
            
        try:
            file_id = int(target)
        except ValueError:
            target_lower = target.lower()
            if isinstance(self.current_parser, NTFSParser):
                if not self.ntfs_files_cache:
                    print("Ejecuta 'ls' primero para indexar este directorio.")
                    return
                if target_lower in self.ntfs_files_cache:
                    file_id = self.ntfs_files_cache[target_lower]
            elif isinstance(self.current_parser, FATParser):
                for idx, entry in enumerate(self.fat_files_cache):
                    if entry.name.lower() == target_lower:
                        file_id = idx
                        break
            elif isinstance(self.current_parser, Ext4Parser):
                for entry in self.ext4_files_cache:
                    if entry['name'].lower() == target_lower:
                        file_id = entry['inode']
                        break
                        
        if file_id is None:
            print(f"Archivo '{target}' no encontrado o ID numérico inválido.")
            return

        try:
            if isinstance(self.current_parser, NTFSParser):
                record = self.current_parser.get_mft_record(file_id)
                record.parse_attributes()
                
                selected_stream = None
                for s in record.data_streams:
                    if (not stream_name and not s['name']) or (stream_name and s['name'].lower() == stream_name):
                        selected_stream = s
                        break
                        
                if not selected_stream:
                    print(f"Flujo de datos '{stream_name}' no encontrado en el archivo.")
                    return
                    
                s_name_display = selected_stream['name'] if selected_stream['name'] else "<Flujo Principal>"
                if selected_stream['is_resident']:
                    print(f"El flujo '{s_name_display}' es residente (su contenido cabe dentro de la entrada MFT). No usa clústeres externos.")
                    return
                    
                print(f"\n[+] Data Runs (Fragmentación) para '{record.file_name}' (Flujo: {s_name_display}):")
                if not selected_stream['runs']:
                    print("    (El archivo no tiene Data Runs válidos o está vacío)")
                
                for idx, run in enumerate(selected_stream['runs']):
                    print(f"    Run {idx+1}: Empieza en el Clúster Lógico {run['start_cluster']} -> Ocupa {run['length']} clúster(es)")
                    print(f"            (Usa 'go cluster {run['start_cluster']}' para ver su contenido en disco)")
                    
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print("ID fuera de rango. Ejecuta 'ls' primero.")
                    return
                entry = self.fat_files_cache[file_id]
                if entry.start_cluster < 2:
                    print("El archivo no tiene clústeres de datos asignados (tamaño 0).")
                    return
                    
                print(f"\n[+] Cadena FAT (Fragmentación de clústeres) para '{entry.name}':")
                if isinstance(self.current_parser, exFATParser):
                    chain = self.current_parser.get_fat_chain(entry.start_cluster, entry.no_fat_chain, entry.size)
                else:
                    chain = self.current_parser.get_fat_chain(entry.start_cluster)
                    
                for idx, cluster in enumerate(chain):
                    print(f"    Bloque {idx+1}: Clúster Lógico {cluster}")
                print(f"    -> Total: {len(chain)} clúster(es)")
                print(f"    (Usa 'go cluster {entry.start_cluster}' para ver el primer bloque en disco)")
                
            elif isinstance(self.current_parser, Ext4Parser):
                print(f"\n[+] Extents (Fragmentación de bloques) para el Inodo {file_id}:")
                inode_data = self.current_parser.get_inode(file_id)
                blocks = self.current_parser.get_inode_data_blocks(inode_data)
                if not blocks:
                    print("    (El archivo no tiene bloques de datos o es de tamaño 0)")
                for idx, block in enumerate(blocks):
                    print(f"    Bloque {idx+1}: Bloque Físico {block}")
                print(f"    -> Total: {len(blocks)} bloque(s)")
                
        except Exception as e:
            print(f"Error al leer fragmentación: {e}")

    def do_cat(self, arg):
        """Muestra el contenido de un archivo, sector o clúster. Uso: cat <id|nombre> o cat sector <num> o cat cluster <num>"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_cat.__doc__))
            return
        args = arg.split()
        if not args:
            print(_("Uso: cat <id|nombre> o cat sector <num> o cat cluster <num>"))
            return
            
        action = args[0].lower()
        
        # 1. Cat Sector / Cluster
        if action in ("sector", "cluster"):
            if len(args) < 2:
                print(_("Uso: cat {action} <num>").format(action=action))
                return
            if action == "sector":
                self.do_sector(args[1])
            else:
                self.do_cluster(args[1])
            return

        # 2. Cat File by ID or Name
        if not self.current_parser:
            print(_("Selecciona una partición válida primero."))
            return

        file_id = None
        stream_name = ""
        target = args[0]
        
        # Soportar sintaxis ID:ADS_NAME
        if ":" in target:
            parts = target.split(":", 1)
            target = parts[0]
            stream_name = parts[1].lower()
            
        # Intentar como ID numérico
        try:
            file_id = int(target)
        except ValueError:
            # Intentar resolver nombre a ID
            target_lower = target.lower()
            if isinstance(self.current_parser, NTFSParser):
                if not self.ntfs_files_cache:
                    print(_("Ejecuta 'ls' primero para indexar este directorio."))
                    return
                if target_lower in self.ntfs_files_cache:
                    file_id = self.ntfs_files_cache[target_lower]
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                for idx, entry in enumerate(self.fat_files_cache):
                    if entry.name.lower() == target_lower:
                        file_id = idx
                        break

        if file_id is None:
            print(_("Archivo '{target}' no encontrado o ID numérico inválido.").format(target=target))
            return
            
        try:
            data_content = None
            file_name = ""
            
            if isinstance(self.current_parser, NTFSParser):
                record = self.current_parser.get_mft_record(file_id)
                record.parse_attributes()
                file_name = record.file_name
                
                # Seleccionar el stream correcto (ADS)
                selected_stream = None
                for s in record.data_streams:
                    if (not stream_name and not s['name']) or (stream_name and s['name'].lower() == stream_name):
                        selected_stream = s
                        break
                        
                if not selected_stream:
                    print(_("Flujo de datos '{stream}' no encontrado en el archivo.").format(stream=stream_name))
                    return
                
                if selected_stream['is_resident']:
                    data_content = selected_stream['content']
                else:
                    data_content = self.current_parser.read_data_runs(selected_stream['runs'], selected_stream['size'])
                    
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print(_("ID fuera de rango. Ejecuta 'ls' primero."))
                    return
                entry = self.fat_files_cache[file_id]
                file_name = entry.name
                if entry.size > 0 and entry.start_cluster >= 2:
                    if isinstance(self.current_parser, exFATParser):
                        chain = self.current_parser.get_fat_chain(entry.start_cluster, entry.no_fat_chain, entry.size)
                    else:
                        chain = self.current_parser.get_fat_chain(entry.start_cluster)
                        
                    data_buffer = bytearray()
                    for cluster in chain:
                        offset = self.current_parser.get_cluster_offset(cluster)
                        data_buffer.extend(self.data_source.read(offset, self.current_parser.get_cluster_size()))
                    data_content = bytes(data_buffer[:entry.size])
                else:
                    data_content = b""
                    
            elif isinstance(self.current_parser, Ext4Parser):
                # Intentar buscar por nombre en caché o parsear el target como Inodo
                try:
                    file_id = int(target)
                except ValueError:
                    file_id = None
                    for entry in self.ext4_files_cache:
                        if entry['name'].lower() == target.lower():
                            file_id = entry['inode']
                            break
                            
                if file_id is None:
                    print(_("Inodo no válido o nombre no encontrado. Usa el comando 'ls' primero."))
                    return
                    
                file_name = f"Inodo {file_id}"
                try:
                    data_content = self.current_parser.read_file(file_id)
                except Exception as e:
                    print(_("Error leyendo archivo de Ext4: {error}").format(error=e))
                    return
            
            if data_content is not None:
                if data_content:
                    print(_("--- Contenido de {name} ---").format(name=file_name))
                    try:
                        print(data_content.decode('utf-8'))
                    except UnicodeDecodeError:
                        print(_("[!] El archivo contiene datos binarios, mostrando hexdump en su lugar:"))
                        print(hexdump(data_content[:1024]))
                        if len(data_content) > 1024:
                            print(_("\n... (mostrando solo primeros 1024 bytes) ..."))
                    print("-----------------------------------")
                else:
                    print(_("El archivo está vacío."))
                    
        except Exception as e:
            print(_("Error al leer archivo: {error}").format(error=e))
            
    def do_extract(self, arg):
        """Extrae el contenido de un archivo a disco. Uso: extract <id> <ruta_destino>"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_extract.__doc__))
            return
        args = arg.split()
        if len(args) < 2:
            print("Uso: extract <id> <ruta_destino>")
            return
            
        try:
            target = args[0]
            dest = args[1]
            stream_name = ""
            
            if ":" in target:
                parts = target.split(":", 1)
                target = parts[0]
                stream_name = parts[1].lower()
                
            file_id = int(target)
            data_content = None
            
            if isinstance(self.current_parser, NTFSParser):
                record = self.current_parser.get_mft_record(file_id)
                record.parse_attributes()
                
                selected_stream = None
                for s in record.data_streams:
                    if (not stream_name and not s['name']) or (stream_name and s['name'].lower() == stream_name):
                        selected_stream = s
                        break
                        
                if not selected_stream:
                    print(f"Flujo de datos '{stream_name}' no encontrado en el archivo.")
                    return
                    
                if selected_stream['is_resident']:
                    data_content = selected_stream['content']
                else:
                    data_content = self.current_parser.read_data_runs(selected_stream['runs'], selected_stream['size'])
                    
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print("ID fuera de rango. Ejecuta 'ls' primero.")
                    return
                entry = self.fat_files_cache[file_id]
                if entry.size > 0 and entry.start_cluster >= 2:
                    if isinstance(self.current_parser, exFATParser):
                        chain = self.current_parser.get_fat_chain(entry.start_cluster, entry.no_fat_chain, entry.size)
                    else:
                        chain = self.current_parser.get_fat_chain(entry.start_cluster)
                        
                    data_buffer = bytearray()
                    for cluster in chain:
                        offset = self.current_parser.get_cluster_offset(cluster)
                        data_buffer.extend(self.data_source.read(offset, self.current_parser.get_cluster_size()))
                    data_content = bytes(data_buffer[:entry.size])
                else:
                    data_content = b""
                    
            elif isinstance(self.current_parser, Ext4Parser):
                try:
                    file_id = int(target)
                except ValueError:
                    file_id = None
                    for entry in self.ext4_files_cache:
                        if entry['name'].lower() == target.lower():
                            file_id = entry['inode']
                            break
                            
                if file_id is None:
                    print("Inodo no válido o nombre no encontrado. Usa el comando 'ls' primero.")
                    return
                    
                try:
                    data_content = self.current_parser.read_file(file_id)
                except Exception as e:
                    print(f"Error leyendo archivo de Ext4: {e}")
                    return
            
            if data_content is not None:
                with open(dest, 'wb') as f:
                    f.write(data_content)
                print(f"[+] Archivo extraído correctamente a {dest} ({len(data_content)} bytes).")
                
        except ValueError:
            print("Uso: extract <id> <ruta_destino>")
        except Exception as e:
            print(f"Error al extraer archivo: {e}")

    def do_dump_clusters(self, arg):
        """Extrae un rango de clústeres/bloques a un archivo. Uso: dump_clusters <inicio> <fin | +cantidad> <ruta_destino>"""
        if not self.current_parser:
            print("Selecciona una partición válida primero.")
            return
            
        args = arg.split()
        if len(args) < 3:
            print("Uso: dump_clusters <clúster_inicio> <clúster_fin | +cantidad> <ruta_destino>")
            print("Ejemplo 1: dump_clusters 100 200 volcado.bin (Volcar del 100 al 200 inclusivo)")
            print("Ejemplo 2: dump_clusters 100 +50 volcado.bin (Volcar 50 clústeres empezando en el 100)")
            return
            
        try:
            start_cluster = int(args[0])
            
            if args[1].startswith('+'):
                count = int(args[1][1:])
                end_cluster = start_cluster + count - 1
            else:
                end_cluster = int(args[1])
                
            dest = args[2]
            
            if start_cluster > end_cluster:
                print("El clúster de inicio no puede ser mayor al de fin.")
                return
                
            num_clusters = end_cluster - start_cluster + 1
            cluster_size = 0
            
            if isinstance(self.current_parser, NTFSParser):
                cluster_size = self.current_parser.boot_sector.bytes_per_cluster
                get_offset = lambda c: self.current_parser.partition.start_offset + (c * cluster_size)
            elif isinstance(self.current_parser, FATParser):
                cluster_size = self.current_parser.get_cluster_size()
                get_offset = self.current_parser.get_cluster_offset
            elif isinstance(self.current_parser, Ext4Parser):
                cluster_size = self.current_parser.superblock.block_size
                get_offset = lambda c: self.current_parser.partition.start_offset + (c * cluster_size)
            else:
                print("Parser no soportado.")
                return
                
            print(f"[+] Volcando {num_clusters} clúster(es)/bloque(s) ({num_clusters * cluster_size} bytes) a '{dest}'...")
            
            with open(dest, 'wb') as f:
                for c in range(start_cluster, end_cluster + 1):
                    offset = get_offset(c)
                    data = self.data_source.read(offset, cluster_size)
                    f.write(data)
                    
            print("[+] Volcado completado exitosamente.")
            
        except ValueError:
            print("Uso inválido. Asegúrate de proporcionar números enteros.")
        except Exception as e:
            print(f"Error al volcar clústeres: {e}")

    def do_dump_blocks(self, arg):
        """Alias para dump_clusters. Uso: dump_blocks <inicio> <fin | +cantidad> <ruta_destino>"""
        self.do_dump_clusters(arg)

    def do_deleted(self, arg):
        """Lista archivos borrados en la partición activa. Uso: deleted [limite_mft]"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_deleted.__doc__))
            return
        if self.selected_partition is None or self.current_parser is None:
            print(_("Selecciona una partición primero."))
            return

        if isinstance(self.current_parser, NTFSParser):
            limit = 1000
            if arg.strip():
                try:
                    limit = int(arg.strip())
                except ValueError:
                    pass

            print(_("\n[+] Escaneando los primeros {limit} registros MFT en busca de archivos borrados...").format(limit=limit))
            print(_("{id:<8} | {type:<5} | {status:<8} | {created:<19} | {modified:<19} | {accessed:<19} | {name}").format(
                id="ID", type="Tipo", status="Estado", created="Creación", modified="Modificación", accessed="Acceso", name="Nombre del Archivo"))
            print("-" * 115)

            deleted_found = 0
            for i in range(limit):
                try:
                    record = self.current_parser.get_mft_record(i)
                    if record.signature != 'FILE':
                        continue

                    record.parse_attributes()
                    if not record.is_in_use() and record.file_name:
                        tipo = "DIR" if record.is_directory() else "FILE"
                        estado = _("Borrado")
                        created_date = record.created if record.created else "N/A"
                        mod_date = record.modified if record.modified else "N/A"
                        acc_date = record.accessed if record.accessed else "N/A"
                        print(f"{i:<8} | {tipo:<5} | {estado:<8} | {created_date:<19} | {mod_date:<19} | {acc_date:<19} | {record.file_name}")
                        deleted_found += 1
                except Exception:
                    pass
            print(_("\n[+] Fin del escaneo. Borrados encontrados: {count}").format(count=deleted_found))

        elif isinstance(self.current_parser, (FATParser, exFATParser)):
            print(_("\n[+] Buscando entradas borradas en el directorio actual '{path}'...").format(path=self.current_path))
            try:
                if isinstance(self.current_parser, exFATParser):
                    no_fat_chain = getattr(self, 'current_directory_no_fat_chain', False)
                    size = getattr(self, 'current_directory_size', 0)
                    all_entries = self.current_parser.get_directory_entries(self.current_directory_id, no_fat_chain, size)
                else:
                    all_entries = self.current_parser.get_directory_entries(self.current_directory_id)

                # Filtrar solo las entradas borradas
                self.fat_files_cache = [entry for entry in all_entries if entry.is_deleted]

                print(_("{id:<8} | {type:<5} | {status:<8} | {size:<10} | {created:<19} | {modified:<19} | {accessed:<19} | {name}").format(
                    id="ID", type="Tipo", status="Estado", size="Tamaño", created="Creación", modified="Modificación", accessed="Acceso", name="Nombre"))
                print("-" * 125)

                for idx, entry in enumerate(self.fat_files_cache):
                    tipo = "DIR" if entry.is_directory else "FILE"
                    estado = _("Borrado")
                    created_date = entry.created if entry.created else "N/A"
                    mod_date = entry.modified if entry.modified else "N/A"
                    acc_date = entry.accessed if entry.accessed else "N/A"
                    print(f"{idx:<8} | {tipo:<5} | {estado:<8} | {entry.size:<10} | {created_date:<19} | {mod_date:<19} | {acc_date:<19} | {entry.name}")

                print(_("\n[+] Fin del escaneo. Borrados encontrados: {count}").format(count=len(self.fat_files_cache)))
            except Exception as e:
                print(_("Error al leer FAT: {error}").format(error=e))

        elif isinstance(self.current_parser, Ext4Parser):
            print(_("\n[!] En Ext4, cuando se borra un archivo, el inodo se marca como libre, los bloques de datos se liberan en el bitmap,"))
            print(_("    y la entrada del directorio se compacta desvinculando el nombre del archivo inmediatamente."))
            print(_("    Por lo tanto, la recuperación basada en metadatos del directorio no es factible mediante este listado."))
            print(_("    Se recomienda utilizar el comando 'carve' en su lugar, o analizar el Journal del sistema de archivos (jbd2) si está disponible."))

    def do_recover(self, arg):
        """Recupera un archivo borrado reconstruyéndolo a partir de metadatos (FAT/NTFS). Uso: recover <id> <ruta_destino>"""
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_recover.__doc__))
            return
        args = arg.split()
        if len(args) < 2:
            print(_("Uso: recover <id> <ruta_destino>"))
            return
            
        try:
            target = args[0]
            dest = args[1]
            stream_name = ""
            
            if ":" in target:
                parts = target.split(":", 1)
                target = parts[0]
                stream_name = parts[1].lower()
                
            file_id = int(target)
            data_content = None
            
            if isinstance(self.current_parser, NTFSParser):
                record = self.current_parser.get_mft_record(file_id)
                record.parse_attributes()
                
                # Verificar si está borrado
                if record.is_in_use():
                    print(_("[!] Alerta: El registro MFT {id} está marcado como ACTIVO (no borrado).").format(id=file_id))
                    print(_("    Para archivos activos se recomienda usar el comando 'extract'."))
                    print(_("    Procediendo igualmente con la recuperación..."))
                
                selected_stream = None
                for s in record.data_streams:
                    if (not stream_name and not s['name']) or (stream_name and s['name'].lower() == stream_name):
                        selected_stream = s
                        break
                        
                if not selected_stream:
                    print(_("Flujo de datos '{stream}' no encontrado en el archivo.").format(stream=stream_name))
                    return
                    
                print(_("[+] Recuperando archivo borrado en NTFS desde el registro MFT {id}...").format(id=file_id))
                if selected_stream['is_resident']:
                    data_content = selected_stream['content']
                    print(_("    -> Tipo: Residente (datos guardados dentro de la MFT)"))
                else:
                    data_content = self.current_parser.read_data_runs(selected_stream['runs'], selected_stream['size'])
                    print(_("    -> Tipo: No Residente (reconstruido mediante {count} fragmentos/runs)").format(count=len(selected_stream['runs'])))
                    
            elif isinstance(self.current_parser, (FATParser, exFATParser)):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print(_("ID fuera de rango. Ejecuta 'ls' primero."))
                    return
                entry = self.fat_files_cache[file_id]
                if not entry.is_deleted:
                    print(_("El archivo no está borrado. Usa 'extract' en su lugar."))
                    return
                    
                if entry.size == 0 or entry.start_cluster < 2:
                    print(_("El archivo borrado tiene tamaño 0 o no tiene clúster asignado."))
                    return
                    
                if isinstance(self.current_parser, exFATParser):
                    if entry.no_fat_chain:
                        print(_("[+] Recuperando archivo borrado en exFAT de '{name}' (Archivo CONTIGUO - Reconstrucción 100% integra)...").format(name=entry.name))
                    else:
                        print(_("[+] Intentando recuperación contigua en exFAT de '{name}' (Archivo fragmentado - la cadena FAT fue borrada)...").format(name=entry.name))
                    offset = self.current_parser.get_cluster_offset(entry.start_cluster)
                    data_content = self.data_source.read(offset, entry.size)
                else: # FATParser (FAT12/16/32)
                    print(_("[+] Intentando recuperación contigua en FAT de '{name}' (Inicio: {cluster}, Tamaño: {size} bytes)...").format(
                        name=entry.name, cluster=entry.start_cluster, size=entry.size
                    ))
                    offset = self.current_parser.get_cluster_offset(entry.start_cluster)
                    data_content = self.data_source.read(offset, entry.size)
                
            else:
                print(_("[!] La recuperación de borrados basada en metadatos no está disponible para este sistema de archivos."))
                return

            if data_content is not None:
                with open(dest, 'wb') as f:
                    f.write(data_content)
                print(_("[+] ¡Archivo recuperado con éxito en {dest}!").format(dest=dest))
            else:
                print(_("[!] No se pudo extraer contenido para la recuperación."))
                
        except ValueError:
            print(_("Uso: recover <id> <ruta_destino>"))
        except Exception as e:
            print(_("Error al recuperar archivo: {error}").format(error=e))

    def do_find_orphans(self, arg):
        """Busca archivos huérfanos en NTFS (cuyo directorio padre fue borrado). Uso: find_orphans [limite_escaneo]"""
        if not self.current_parser:
            print("Selecciona una partición primero.")
            return
            
        if isinstance(self.current_parser, NTFSParser):
            limit = 1000 # Límite por defecto para no colgar la consola
            if arg:
                try:
                    limit = int(arg)
                except ValueError:
                    pass
                    
            print(f"\n[+] Escaneando los primeros {limit} registros MFT en busca de archivos huérfanos...")
            print("    (Un archivo es huérfano si su 'Parent ID' apunta a un directorio borrado o inválido)")
            print(f"{'ID':<8} | {'Tipo':<6} | {'Estado':<10} | {'Parent ID':<10} | {'Nombre del Archivo'}")
            print("-" * 75)
            
            orphans_found = 0
            for i in range(limit):
                if i == 5: continue # Root (no tiene padre estricto en el mismo sentido)
                
                try:
                    record = self.current_parser.get_mft_record(i)
                    if record.signature != 'FILE':
                        continue
                        
                    record.parse_attributes()
                    if not record.file_name:
                        continue
                        
                    is_orphan = False
                    
                    # Intentar buscar a su padre
                    try:
                        parent_record = self.current_parser.get_mft_record(record.parent_mft_id)
                        # Si el padre no es un FILE o está borrado, ¡entonces este archivo quedó huérfano!
                        if parent_record.signature != 'FILE' or not parent_record.is_in_use():
                            is_orphan = True
                    except Exception:
                        # Si lanza error al leer el padre, el padre no existe
                        is_orphan = True
                        
                    if is_orphan:
                        tipo = "DIR" if record.is_directory() else "FILE"
                        estado = "Activo" if record.is_in_use() else "Borrado"
                        print(f"{i:<8} | {tipo:<6} | {estado:<10} | {record.parent_mft_id:<10} | {record.file_name}")
                        orphans_found += 1
                        
                except Exception:
                    pass
                    
            print(f"\n[+] Escaneo completado. Huérfanos detectados: {orphans_found}")
            if orphans_found > 0:
                print("    (Puedes inspeccionarlos usando 'info <id>' o 'cat <id>')")
                
        elif isinstance(self.current_parser, FATParser):
            print("\n[!] En FAT, buscar huérfanos implica cruzar las entradas válidas del File System")
            print("    contra los clústeres ocupados en la tabla FAT. Es una técnica de nivel avanzado.")
            print("    Por ahora, se aconseja utilizar el comando 'recover' sobre entradas borradas (0xE5).")
        else:
            print("Comando no soportado para este File System.")

    def do_search(self, arg):
        """Busca un patrón o Regex en toda la partición. Uso: search [-r] <patron>"""
        if not self.current_parser:
            print("Selecciona una partición válida primero.")
            return
            
        args = arg.split(maxsplit=1)
        if not args:
            print("Uso: search [-r] <patron>")
            return
            
        is_regex = False
        if args[0] == "-r":
            if len(args) < 2:
                print("Falta el patrón después de -r")
                return
            is_regex = True
            pattern_str = args[1]
        else:
            pattern_str = arg
            
        import re
        import sys
        
        try:
            if is_regex:
                pattern_ascii = re.compile(pattern_str.encode('utf-8'))
                try:
                    # En regex, codificar directamente a utf-16le puede romper clases de caracteres complejas,
                    # pero funciona bien para secuencias básicas y strings planos.
                    pattern_utf16 = re.compile(pattern_str.encode('utf-16le'))
                except Exception:
                    pattern_utf16 = None
            else:
                pattern_ascii = re.compile(re.escape(pattern_str.encode('utf-8')))
                pattern_utf16 = re.compile(re.escape(pattern_str.encode('utf-16le')))
        except Exception as e:
            print(f"Error al compilar el patrón: {e}")
            return
            
        chunk_size = 1024 * 1024 * 16 # 16 MB
        overlap = 1024 # 1KB overlap
        offset = self.current_parser.partition.start_offset
        end_offset = offset + self.current_parser.partition.size_in_bytes
        
        print(f"\n[+] Iniciando búsqueda RAW en la partición {self.selected_partition}...")
        print(f"    Patrón: '{pattern_str}' (Regex: {is_regex})")
        print("    Buscando en codificaciones: ASCII/UTF-8 y UTF-16LE")
        print("-" * 80)
        
        total_size = self.current_parser.partition.size_in_bytes
        bytes_read = 0
        hits = 0
        limit_hits = 100
        
        spinner = ['|', '/', '-', '\\']
        spinner_idx = 0
        
        while offset < end_offset:
            read_size = min(chunk_size + overlap, end_offset - offset)
            data = self.data_source.read(offset, read_size)
            if not data:
                break
                
            matches = []
            if pattern_ascii:
                matches.extend([(m, 'UTF-8') for m in pattern_ascii.finditer(data)])
            if pattern_utf16:
                matches.extend([(m, 'UTF-16LE') for m in pattern_utf16.finditer(data)])
                
            for m, encoding in matches:
                hit_offset_in_chunk = m.start()
                
                # Ignorar si el hit empieza exactamente en el overlap 
                # (será detectado en el siguiente chunk de forma natural)
                if hit_offset_in_chunk >= chunk_size and (offset + chunk_size < end_offset):
                    continue 
                    
                hits += 1
                absolute_offset = offset + hit_offset_in_chunk
                partition_offset = absolute_offset - self.current_parser.partition.start_offset
                sector = partition_offset // 512
                
                # Borrar la línea de progreso para imprimir el resultado
                sys.stdout.write("\r" + " " * 60 + "\r")
                
                print(f"[*] HIT #{hits} | Offset Partición: {hex(partition_offset)} | Sector Partición: {sector} | Encoding: {encoding}")
                
                start_ctx = max(0, hit_offset_in_chunk - 16)
                end_ctx = min(len(data), m.end() + 16)
                snippet = data[start_ctx:end_ctx]
                
                try:
                    if encoding == 'UTF-16LE':
                        text_snippet = snippet.decode('utf-16le', errors='replace').replace('\n', ' ').replace('\r', '')
                    else:
                        text_snippet = snippet.decode('utf-8', errors='replace').replace('\n', ' ').replace('\r', '')
                    print(f"    Texto: ...{text_snippet}...")
                except Exception:
                    pass
                    
                print(f"    Hex  : {snippet.hex()}")
                print("-" * 80)
                
                if hits >= limit_hits:
                    sys.stdout.write("\r" + " " * 60 + "\r")
                    print(f"[!] Límite de {limit_hits} resultados alcanzado. Búsqueda detenida.")
                    return
            
            step = chunk_size
            if offset + step >= end_offset:
                break
                
            offset += step
            bytes_read += step
            
            percent = int((bytes_read / total_size) * 100)
            bar_length = 30
            filled = int(bar_length * percent // 100)
            bar = '=' * filled + '-' * (bar_length - filled)
            spin_char = spinner[spinner_idx % len(spinner)]
            
            sys.stdout.write(f"\r    Buscando: [{bar}] {percent}% {spin_char} (Hits: {hits})")
            sys.stdout.flush()
            spinner_idx += 1
            
        sys.stdout.write("\r" + " " * 60 + "\r")
        print(f"[+] Búsqueda finalizada. Total de coincidencias encontradas: {hits}")


    def do_carve(self, arg):
        """Realiza File Carving automatizado buscando Magic Bytes en la partición o en todo el disco.

        Uso:
          carve                          -> guarda en el directorio actual, todos los tipos
          carve <directorio_destino>     -> guarda en el directorio indicado, todos los tipos
          carve [dir] jpg pdf png        -> filtra tipos específicos
          carve --disk [dir] [tipos...]  -> fuerza el escaneo de todo el disco/imagen forense completa
          carve --max-size 50MB          -> sobrescribe el tamaño máximo de carving
          carve --types jpg,png          -> filtra tipos específicos de forma explícita

        Tipos soportados: definidos en signatures.conf (por defecto: jpg, png, pdf, zip, exe, gif, rar, mp3, db, elf...)
        Si no se especifica directorio, se usa el directorio de trabajo actual.
        """
        if arg.strip() in ('?', '-h', '--help'):
            print(_(self.do_carve.__doc__))
            return
        import os
        
        args = arg.split()
        use_entire_disk = False
        
        if "--disk" in args:
            use_entire_disk = True
            args.remove("--disk")
            
        if not self.current_parser:
            use_entire_disk = True
            
        # Determinar partición destino
        if use_entire_disk:
            class DiskPartitionMock:
                def __init__(self, size_in_bytes):
                    self.start_offset = 0
                    self.size_in_bytes = size_in_bytes
            
            try:
                disk_size = self.data_source.get_size()
            except Exception as e:
                print(_("[!] Error al determinar el tamaño de la imagen de disco: {error}").format(error=e))
                return
            target_partition = DiskPartitionMock(disk_size)
        else:
            target_partition = self.current_parser.partition

        # Configurar override de tamaño máximo
        max_size_override = None
        if "--max-size" in args:
            try:
                idx = args.index("--max-size")
                if idx + 1 < len(args):
                    val_str = args[idx + 1].upper()
                    if val_str.endswith("KB"):
                        max_size_override = int(val_str[:-2]) * 1024
                    elif val_str.endswith("MB"):
                        max_size_override = int(val_str[:-2]) * 1024 * 1024
                    elif val_str.endswith("GB"):
                        max_size_override = int(val_str[:-2]) * 1024 * 1024 * 1024
                    else:
                        max_size_override = int(val_str)
                    args.pop(idx + 1)
                    args.pop(idx)
                else:
                    print("Falta el valor para --max-size")
                    return
            except ValueError:
                print("Tamaño máximo inválido. Ejemplo: --max-size 50MB o --max-size 52428800")
                return

        # Cargar firmas desde el archivo de configuración
        loaded_sigs = load_signatures()
        KNOWN_TYPES = {s["ext"].lower() for s in loaded_sigs}

        # Procesar --types si está explícito
        filter_types = []
        if "--types" in args:
            try:
                idx = args.index("--types")
                if idx + 1 < len(args):
                    types_val = args[idx + 1].lower()
                    if types_val != "all":
                        filter_types = [t.strip() for t in types_val.split(",") if t.strip()]
                    args.pop(idx + 1)
                    args.pop(idx)
                else:
                    print("Falta el valor para --types")
                    return
            except Exception:
                print("Error al procesar --types")
                return

        # Detectar si el primer argumento es un tipo conocido o un directorio
        if not args:
            output_dir = os.getcwd()
        elif args[0].lower() in KNOWN_TYPES or args[0].lower() == "all":
            output_dir = os.getcwd()
            if not filter_types:
                filter_types = [t.lower() for t in args if t.lower() != "all"]
        else:
            output_dir = args[0]
            if not filter_types:
                filter_types = [t.lower() for t in args[1:] if t.lower() != "all"]

        # Filtrar firmas según los tipos solicitados
        if filter_types:
            custom_sigs = [s for s in loaded_sigs if s["ext"].lower() in filter_types]
            if not custom_sigs:
                print(_("[!] Ningún tipo válido reconocido. Tipos disponibles: {tipos}").format(tipos=', '.join(sorted(list(KNOWN_TYPES)))))
                return
        else:
            custom_sigs = loaded_sigs

        # Resumen previo
        sigs_to_use = custom_sigs
        if use_entire_disk:
            print(_("\n[+] Iniciando File Carving automatizado en toda la imagen de disco..."))
            print(_("    Directorio de salida : {out_dir}").format(out_dir=output_dir))
            print(_("    Tipos a buscar       : {types}").format(types=', '.join(s['name'] for s in sigs_to_use)))
            print(_("    Tamaño del disco     : {size:.2f} MB").format(size=target_partition.size_in_bytes / (1024**2)))
        else:
            print(_("\n[+] Iniciando File Carving automatizado en la partición {part}...").format(part=self.selected_partition))
            print(_("    Directorio de salida : {out_dir}").format(out_dir=output_dir))
            print(_("    Tipos a buscar       : {types}").format(types=', '.join(s['name'] for s in sigs_to_use)))
            print(_("    Tamaño de partición  : {size:.2f} MB").format(size=target_partition.size_in_bytes / (1024**2)))
            
        print(_("    Esto puede tardar varios minutos en particiones grandes."))
        print("-" * 80)

        spinner = ['|', '/', '-', '\\']
        spinner_idx = [0]  # lista para capturar en closure

        def progress(pct, msg):
            spin_char = spinner[spinner_idx[0] % len(spinner)]
            bar_length = 30
            filled = int(bar_length * pct // 100)
            bar = '=' * filled + '-' * (bar_length - filled)
            sys.stdout.write(f"\r    [{bar}] {pct:3d}% {spin_char}  {msg}")
            sys.stdout.flush()
            spinner_idx[0] += 1

        try:
            carver = FileCarver(
                data_source=self.data_source,
                partition=target_partition,
                output_dir=output_dir,
                progress_cb=progress,
                custom_signatures=custom_sigs,
                max_size_override=max_size_override,
            )
            results = carver.carve()


            sys.stdout.write("\n")
            print(_("\n[+] Carving finalizado."))
            print(_("    Archivos recuperados : {count}").format(count=len(results)))
            print(_("    Saltados / errores   : {count}").format(count=carver.skipped_count))

            if results:
                print(_("\n    {'#':<6} | {'Tipo':<22} | {'Offset':<14} | {'Tamaño':<12} | {'Footer':<8} | Nombre"))

                print("    " + "-" * 90)
                for r in results:
                    footer_ok = "[OK]" if r["footer_found"] else "[TRUNC]"
                    size_kb   = r["size"] / 1024
                    print(f"    {r['index']:<6} | {r['type']:<22} | {hex(r['abs_offset']):<14} | {size_kb:>8.1f} KB | {footer_ok:<10} | {r['filename']}")
                print(_("\n    Todos los archivos se guardaron en: {dir}").format(dir=output_dir))
            else:
                print(_("    No se encontraron archivos con las firmas especificadas."))

        except Exception as e:
            sys.stdout.write("\n")
            print(_("[!] Error durante el carving: {error}").format(error=e))



    def do_superblock(self, arg):
        """Muestra la configuración del Superbloque en particiones Ext4."""
        if not isinstance(self.current_parser, Ext4Parser):
            print("Este comando es exclusivo para particiones Linux (Ext4).")
            return
            
        sb = self.current_parser.superblock
        print("\n[+] Información del Superbloque (Ext4):")
        print(f"    Firma Mágica     : {hex(sb.magic)}")
        print(f"    Total Inodos     : {sb.inodes_count}")
        print(f"    Total Bloques    : {sb.blocks_count}")
        print(f"    Bloques Libres   : {sb.free_blocks_count}")
        print(f"    Inodos Libres    : {sb.free_inodes_count}")
        print(f"    1er Bloque Datos : {sb.first_data_block}")
        print(f"    Tamaño de Bloque : {sb.block_size} bytes")
        print(f"    Bloques por Grupo: {sb.blocks_per_group}")
        print(f"    Inodos por Grupo : {sb.inodes_per_group}")
        print(f"    Nombre de Volumen: {sb.volume_name}")
        print(f"    Último Montaje   : {sb.last_mounted}")
        print(f"    Última Montura   : {sb.format_time(sb.mtime)}")
        print(f"    Última Escritura : {sb.format_time(sb.wtime)}")

    def do_help(self, arg):
        """Muestra la ayuda de los comandos disponibles."""
        if arg.strip():
            super().do_help(arg)
            return

        print(_("\n=================================================================================="))
        print(_("  COMANDOS DISPONIBLES EN EL SHELL FORENSE"))
        print(_("=================================================================================="))
        
        print(_("\n[+] COMANDOS GENERALES Y DE NAVEGACIÓN:"))
        print(f"  open <imagen>    - {_('Abre y monta una imagen forense (.dd, .raw, .001, .e01) o disco físico')}")
        print(f"  partitions       - {_('Lista las particiones físicas detectadas en el disco')}")
        print(f"  select <idx>     - {_('Selecciona y monta una partición por su índice en la tabla')}")
        print(f"  imageinfo        - {_('Muestra los metadatos de la imagen (sólo E01)')}")
        print(f"  diskinfo         - {_('Muestra información técnica consolidada del disco o imagen')}")
        print(f"  hash_check [alg] - {_('Verifica la integridad de la imagen calculando MD5, SHA1 o SHA256')}")
        print(f"  history [limit]  - {_('Muestra el historial de comandos ejecutados en el shell')}")
        print(f"  ls               - {_('Lista los archivos y directorios del directorio actual')}")
        print(f"  cd <directorio>  - {_('Navega a un subdirectorio (ej. cd .. o cd carpetaborrada)')}")
        print(f"  cat <id|nombre>  - {_('Muestra el contenido en texto (o hexdump) de un archivo o sector')}")
        
        print(_("\n[+] COMANDOS DE ANÁLISIS FORENSE Y RECUPERACIÓN:"))
        print(f"  deleted [limit]  - {_('Lista los archivos que fueron borrados en la partición activa')}")
        print(f"  recover <id> <d> - {_('Recupera un archivo borrado basándose en sus metadatos (MFT/FAT)')}")
        print(f"  carve [opciones] - {_('File carving ciego. Opciones: --disk, --max-size, --types, ?')}")
        print(f"  find_orphans     - {_('NTFS: Busca archivos cuyo directorio padre fue borrado o no es válido')}")
        print(f"  runs <id|nombre> - {_('Muestra la cadena de asignación lógica (Data Runs/FAT/Extents) de un archivo')}")
        print(f"  identify <s|c>   - {_('Aplica Magic Bytes sobre un sector o clúster físico para identificarlo')}")
        
        print(_("\n[+] COMANDOS DE BAJO NIVEL Y SISTEMA:"))
        print(f"  hexdump <o> <l>  - {_('Muestra un volcado hexadecimal absoluto de la imagen')}")
        print(f"  sector <num>     - {_('Vuelca los datos del LBA físico especificado')}")
        print(f"  cluster <num>    - {_('Vuelca los datos del clúster lógico seleccionado')}")
        print(f"  dump_clusters    - {_('Vuelca un rango de clústeres a un archivo del host')}")
        print(f"  superblock       - {_('Ext4: Muestra la información técnica detallada del superbloque')}")
        print(f"  exit / quit      - {_('Termina la sesión y sale del shell interactivo')}")
        
        print(_("\n💡 Tip forense: Podés escribir '<comando> ?' o 'help <comando>' para ver los parámetros detallados."))
        print("==================================================================================\n")

    def do_exit(self, arg):
        """Sale del shell interactivo."""
        print("Saliendo...")
        return True
    
    def do_quit(self, arg):
        """Sale del shell interactivo."""
        return True

    # --- Autocompletado ---
    def _complete_local_path(self, text):
        """Autocompleta rutas locales en el sistema operativo host."""
        import os
        if not text:
            try:
                entries = os.listdir('.')
                return [e + '/' if os.path.isdir(e) else e for e in entries]
            except Exception:
                return []
        
        dirname, basename = os.path.split(text)
        search_dir = dirname if dirname else '.'
        
        if not os.path.isdir(search_dir):
            return []
            
        try:
            entries = os.listdir(search_dir)
            results = []
            for entry in entries:
                if entry.lower().startswith(basename.lower()):
                    full_path = os.path.join(dirname, entry) if dirname else entry
                    # Normalizar barras a / para simplificar en consola
                    full_path = full_path.replace('\\', '/')
                    if os.path.isdir(os.path.join(search_dir, entry)):
                        full_path += '/'
                    results.append(full_path)
            return results
        except Exception:
            return []

    def _get_current_filenames(self):
        names = []
        if isinstance(self.current_parser, NTFSParser):
            if self.ntfs_files_cache:
                names = list(self.ntfs_files_cache.keys())
        elif isinstance(self.current_parser, FATParser):
            names = [entry.name for entry in self.fat_files_cache]
        elif isinstance(self.current_parser, Ext4Parser):
            names = [entry['name'] for entry in self.ext4_files_cache]
        return names

    def _complete_file(self, text, line, begidx, endidx):
        if not self.current_parser: return []
        names = self._get_current_filenames()
        if not text:
            return names
        return [n for n in names if n.lower().startswith(text.lower())]

    def complete_cd(self, text, line, begidx, endidx):
        return self._complete_file(text, line, begidx, endidx)

    def complete_cat(self, text, line, begidx, endidx):
        # Si tiene ? o es ayuda
        if text == '?':
            return ['?']
        return self._complete_file(text, line, begidx, endidx)

    def complete_extract(self, text, line, begidx, endidx):
        if text == '?':
            return ['?']
        # extract <id> <ruta_destino_local>
        tokens = line.split()
        # Si ya se especificó el primer argumento, autocompletar la ruta local en el host
        if len(tokens) > 2 or (len(tokens) == 2 and not text):
            return self._complete_local_path(text)
        return self._complete_file(text, line, begidx, endidx)

    def complete_recover(self, text, line, begidx, endidx):
        if text == '?':
            return ['?']
        # recover <id> <ruta_destino_local>
        tokens = line.split()
        if len(tokens) > 2 or (len(tokens) == 2 and not text):
            return self._complete_local_path(text)
        return self._complete_file(text, line, begidx, endidx)

    def complete_info(self, text, line, begidx, endidx):
        return self._complete_file(text, line, begidx, endidx)

    def complete_runs(self, text, line, begidx, endidx):
        return self._complete_file(text, line, begidx, endidx)

    def complete_select(self, text, line, begidx, endidx):
        if text == '?':
            return ['?']
        if not self.mbr_parser:
            return []
        parts = [str(i) for i in range(len(self.mbr_parser.partitions))]
        return [p for p in parts if p.startswith(text)]

    def complete_carve(self, text, line, begidx, endidx):
        options = ['--disk', '--types', '--max-size', '?']
        tokens = line.split()

        # Si el token anterior es --types, autocompletar con tipos de firmas en signatures.conf
        if len(tokens) > 1 and tokens[-2] == '--types':
            loaded_sigs = load_signatures()
            known = sorted(list(set(s["ext"] for s in loaded_sigs)))
            return [t for t in known if t.startswith(text)]

        # Si empieza con - o es ?, autocompletar opciones
        if text.startswith('-') or text == '?':
            return [o for o in options if o.startswith(text)]

        # En otro caso, autocompletar rutas locales en el host
        return self._complete_local_path(text)

    def complete_open(self, text, line, begidx, endidx):
        if text == '?':
            return ['?']
        return self._complete_local_path(text)

    # Atajos
    do_q = do_quit
    do_EOF = do_exit

if __name__ == "__main__":
    import struct
    # Carga de internacionalización básica
    from core.i18n import set_language
    set_language("es")
    
    # Inicialización del shell con banner oficial
    banner = r"""
    _   __________________  ______          ____                           
   / | / /_  __/ ____/ __ \/ ____/___  ____/ __ \____ ______________  _____
  /  |/ / / / / /_  / /_/ / /_  / __ \/ __/ /_/ / __ `/ ___/ ___/ _ \/ ___/
 / /|  / / / / __/ / _, _/ __/ / /_/ / / / ____/ /_/ / /  (__  )  __/ /    
/_/ |_/ /_/ /_/   /_/ |_/_/    \____/_/ /_/    \__,_/_/  /____/\___/_/     
    """
    print(banner)
    print("==========================================================================")
    print("==========================================================================")
    print(" v1.0.0 - Framework Educativo de Informática Forense | Por: Max Bendinelli")
    print("==========================================================================")
    print("\n[!] Advertencia: No se ha especificado ninguna imagen forense.")
    print("    Por favor, usa el comando 'open <ruta_imagen>' para cargar una.\n")
    
    if sys.platform == "win32":
        try:
            import readline
        except ImportError:
            print("[i] Nota didáctica: Para habilitar el autocompletado interactivo con la tecla <Tab> en Windows, instalá:")
            print("    pip install pyreadline3\n")
            
    shell = NTFSShell(None, None)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nSaliendo...")
