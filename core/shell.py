import cmd
import sys
from core.i18n import _
from core.data_source import DataSource
from core.utils import hexdump, print_breakdown
from fs.ntfs_parser import NTFSParser
from fs.fat_parser import FATParser
from fs.ext4_parser import Ext4Parser
from fs.exfat_parser import exFATParser
from fs.carver import FileCarver, SIGNATURES

class NTFSShell(cmd.Cmd):
    @property
    def intro(self):
        return _("\nBienvenido al Shell Interactivo Forense.\nEscribe 'help' o '?' para listar los comandos.\n")
        
    prompt = "Forense > "

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

    def update_prompt(self):
        if self.selected_partition is None:
            self.prompt = "Forense > "
        else:
            self.prompt = f"Forense [Part {self.selected_partition} | {self.current_path}] > "

    # --- Comandos Generales ---
    
    def do_partitions(self, arg):
        """Lista las particiones encontradas en el disco."""
        if not self.mbr_parser.partitions:
            print(_("No se encontraron particiones."))
            return
            
        print(_("\nParticiones disponibles:"))
        for idx, part in enumerate(self.mbr_parser.partitions):
            boot = "*" if part.bootable else " "
            size_mb = part.size_in_bytes / (1024**2)
            print(_("  [{idx}] {boot} {type_name} | Offset: {start_offset} | Tamaño: {size_mb:.2f} MB").format(
                idx=idx, boot=boot, type_name=part.type_name, 
                start_offset=part.start_offset, size_mb=size_mb))
        print("")

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
            
            # 1. Deteccion exFAT
            if len(sect0) >= 11 and sect0[3:11] == b'EXFAT   ':
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
        """Lista archivos en el directorio actual."""
        if self.selected_partition is None or self.current_parser is None:
            print(_("Selecciona una partición primero."))
            return
            
        if isinstance(self.current_parser, NTFSParser):
            print(_("\n[+] Escaneando registros MFT apuntando a '{path}' (Parent ID: {dir_id})...").format(path=self.current_path, dir_id=self.current_directory_id))
            print(_("{id:<8} | {type:<6} | {status:<10} | {mod:<20} | {name}").format(id="ID", type="Tipo", status="Estado", mod="Modificación", name="Nombre del Archivo"))
            print("-" * 80)
            
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
                        mod_date = record.modified if record.modified else "N/A"
                        
                        print(f"{i:<8} | {tipo:<6} | {estado:<10} | {mod_date:<20} | {record.file_name}")
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
                    
                print(_("{id:<8} | {type:<6} | {status:<10} | {size:<10} | {mod:<20} | {name}").format(id="ID", type="Tipo", status="Estado", size="Tamaño", mod="Modificación", name="Nombre"))
                print("-" * 90)
                for idx, entry in enumerate(self.fat_files_cache):
                    tipo = "DIR" if entry.is_directory else "FILE"
                    estado = _("Borrado") if entry.is_deleted else _("Activo")
                    mod_date = entry.modified if entry.modified else "N/A"
                    print(f"{idx:<8} | {tipo:<6} | {estado:<10} | {entry.size:<10} | {mod_date:<20} | {entry.name}")
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

    def do_recover(self, arg):
        """Recupera un archivo borrado reconstruyéndolo a partir de metadatos (FAT/NTFS). Uso: recover <id> <ruta_destino>"""
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
          carve                          → guarda en el directorio actual, todos los tipos
          carve <directorio_destino>     → guarda en el directorio indicado, todos los tipos
          carve [dir] jpg pdf png        → filtra tipos específicos
          carve --disk [dir] [tipos...]  → fuerza el escaneo de todo el disco/imagen forense completa

        Tipos soportados: jpg, png, pdf, zip, exe, gif, rar, mp3, db, elf
        Si no se especifica directorio, se usa el directorio de trabajo actual.
        """
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

        KNOWN_TYPES = {s["ext"].lower() for s in SIGNATURES}

        # Detectar si el primer argumento es un tipo conocido o un directorio
        if not args:
            # Sin argumentos: usar directorio actual
            output_dir = os.getcwd()
            filter_types = []
        elif args[0].lower() in KNOWN_TYPES:
            # El primer arg ya es un tipo de archivo, no un directorio
            output_dir = os.getcwd()
            filter_types = [t.lower() for t in args]
        else:
            # El primer arg es el directorio destino
            output_dir = args[0]
            filter_types = [t.lower() for t in args[1:]]

        # Filtrar firmas según los tipos solicitados
        if filter_types:
            custom_sigs = [s for s in SIGNATURES if s["ext"].lower() in filter_types]
            if not custom_sigs:
                print(_("[!] Ningún tipo válido reconocido. Tipos disponibles: {tipos}").format(tipos=', '.join(s['ext'] for s in SIGNATURES)))
                return
        else:
            custom_sigs = None  # Usar todas las firmas

        # Resumen previo
        sigs_to_use = custom_sigs if custom_sigs else SIGNATURES
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

    def do_exit(self, arg):
        """Sale del shell interactivo."""
        print("Saliendo...")
        return True
    
    def do_quit(self, arg):
        """Sale del shell interactivo."""
        return True

    # --- Autocompletado ---
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
        return self._complete_file(text, line, begidx, endidx)

    def complete_extract(self, text, line, begidx, endidx):
        return self._complete_file(text, line, begidx, endidx)

    def complete_info(self, text, line, begidx, endidx):
        return self._complete_file(text, line, begidx, endidx)

    def complete_runs(self, text, line, begidx, endidx):
        return self._complete_file(text, line, begidx, endidx)


    # Atajos
    do_q = do_quit
    do_EOF = do_exit
