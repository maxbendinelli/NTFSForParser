import cmd
import sys
from core.i18n import _
from core.data_source import DataSource
from core.utils import hexdump, print_breakdown
from fs.ntfs_parser import NTFSParser
from fs.fat_parser import FATParser
from fs.ext4_parser import Ext4Parser
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
            print("No hay metadatos adicionales disponibles para este formato de imagen (Solo disponible en E01).")
            return
            
        print("\n[+] Metadatos de la Imagen Forense:")
        for k, v in metadata.items():
            # Traducir o limpiar las claves si es necesario, por ahora se muestran directo
            print(f"    - {k}: {v.decode('utf-8') if isinstance(v, bytes) else v}")

    def do_hash_check(self, arg):
        """Verifica el hash MD5 de la imagen cargada. Uso: hash_check"""
        print("\n[!] Calculando el hash MD5 de la imagen completa...")
        print("    Esto puede tardar varios minutos dependiendo del tamaño de la imagen.")
        
        import hashlib
        import sys
        
        md5 = hashlib.md5()
        chunk_size = 1024 * 1024 * 16 # 16 MB
        offset = 0
        total_size = self.data_source.get_size()
        
        spinner = ['|', '/', '-', '\\']
        spinner_idx = 0
        
        try:
            while offset < total_size:
                data = self.data_source.read(offset, min(chunk_size, total_size - offset))
                if not data:
                    break
                md5.update(data)
                offset += len(data)
                
                percent = int((offset / total_size) * 100)
                bar_length = 40
                filled = int(bar_length * percent // 100)
                bar = '=' * filled + '-' * (bar_length - filled)
                
                spin_char = spinner[spinner_idx % len(spinner)]
                sys.stdout.write(f"\r    Progreso: [{bar}] {percent}% {spin_char}")
                sys.stdout.flush()
                
                spinner_idx += 1
            
            sys.stdout.write(f"\r    Progreso: [{'=' * 40}] 100% ✓\n")
            calculated_hash = md5.hexdigest()
            print(f"\n[+] Hash MD5 Calculado: {calculated_hash}")
            
            # Verificar si es E01 comparando con el almacenado
            metadata = self.data_source.get_metadata()
            if metadata:
                # Buscar el hash almacenado (las claves de pyewf suelen ser 'MD5 hash' o similares)
                stored_hash = None
                for k, v in metadata.items():
                    if 'md5' in k.lower():
                        stored_hash = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                        break
                        
                if stored_hash:
                    print(f"[+] Hash MD5 Almacenado (E01): {stored_hash}")
                    if calculated_hash.lower() == stored_hash.lower():
                        print("    -> [VERIFICACIÓN EXITOSA] Los hashes COINCIDEN.")
                    else:
                        print("    -> [ALERTA] Los hashes NO COINCIDEN. La imagen podría estar alterada o corrupta.")
                else:
                    print("[!] Formato E01, pero no se encontró un hash MD5 en los metadatos para verificar.")
            else:
                print("    -> Formato RAW/DD. No hay hash original contra qué comparar.")
                
        except Exception as e:
            print(f"\n[!] Error durante el cálculo del hash: {e}")

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
            
            # Inicializar parser según el tipo
            if part.type_code == 0x07:
                self.current_parser = NTFSParser(self.data_source, part)
                self.current_directory_id = 5 # Root MFT ID
                print(_("    Sistema de archivos detectado: NTFS"))
            elif part.type_code in (0x0B, 0x0C):
                self.current_parser = FATParser(self.data_source, part)
                self.current_directory_id = self.current_parser.boot_sector.root_cluster
                if self.current_directory_id == 0: self.current_directory_id = 2
                print(_("    Sistema de archivos detectado: FAT32"))
            elif part.type_code == 0x83:
                self.current_parser = Ext4Parser(self.data_source, part)
                self.current_directory_id = 2 # Inodo root de ext4
                print(_("    Sistema de archivos detectado: Ext4 (Linux)"))
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
            
        elif isinstance(self.current_parser, FATParser):
            print(_("\n[+] Leyendo directorio '{path}' (Clúster: {dir_id})...").format(path=self.current_path, dir_id=self.current_directory_id))
            try:
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
            elif isinstance(self.current_parser, FATParser):
                for entry in self.fat_files_cache:
                    if entry.name == "..":
                        self.current_directory_id = entry.start_cluster
                        if self.current_directory_id == 0:
                            self.current_directory_id = 2 # Root fallback
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
                    
            elif isinstance(self.current_parser, FATParser):
                for entry in self.fat_files_cache:
                    if entry.name.lower() == target.lower():
                        if entry.is_directory:
                            self.current_directory_id = entry.start_cluster
                            if self.current_directory_id == 0:
                                self.current_directory_id = 2
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
                    
            elif isinstance(self.current_parser, FATParser):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print("ID fuera de rango. Ejecuta 'ls' primero.")
                    return
                entry = self.fat_files_cache[file_id]
                if entry.start_cluster < 2:
                    print("El archivo no tiene clústeres de datos asignados (tamaño 0).")
                    return
                    
                print(f"\n[+] Cadena FAT (Fragmentación de clústeres) para '{entry.name}':")
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
            elif isinstance(self.current_parser, FATParser):
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
                    
            elif isinstance(self.current_parser, FATParser):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print(_("ID fuera de rango. Ejecuta 'ls' primero."))
                    return
                entry = self.fat_files_cache[file_id]
                file_name = entry.name
                if entry.size > 0 and entry.start_cluster >= 2:
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
                    
            elif isinstance(self.current_parser, FATParser):
                if file_id < 0 or file_id >= len(self.fat_files_cache):
                    print("ID fuera de rango. Ejecuta 'ls' primero.")
                    return
                entry = self.fat_files_cache[file_id]
                if entry.size > 0 and entry.start_cluster >= 2:
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
        """Recupera un archivo borrado en FAT asumiendo que sus clústeres son contiguos. Uso: recover <id> <ruta_destino>"""
        args = arg.split()
        if len(args) < 2:
            print("Uso: recover <id> <ruta_destino>")
            return
            
        try:
            file_id = int(args[0])
            dest = args[1]
            
            if not isinstance(self.current_parser, FATParser):
                print("El comando 'recover' actualmente está diseñado para recuperación contigua en FAT.")
                return
                
            if file_id < 0 or file_id >= len(self.fat_files_cache):
                print("ID fuera de rango. Ejecuta 'ls' primero.")
                return
                
            entry = self.fat_files_cache[file_id]
            if not entry.is_deleted:
                print("El archivo no está borrado. Usa 'extract' en su lugar.")
                return
                
            if entry.size == 0 or entry.start_cluster < 2:
                print("El archivo borrado tiene tamaño 0 o no tiene clúster asignado.")
                return
                
            # Recuperación contigua (Carving a ciegas basado en el metadata borrado)
            print(f"[+] Intentando recuperación de '{entry.name}' (Clúster inicio: {entry.start_cluster}, Tamaño: {entry.size} bytes)...")
            
            offset = self.current_parser.get_cluster_offset(entry.start_cluster)
            data_content = self.data_source.read(offset, entry.size)
            
            with open(dest, 'wb') as f:
                f.write(data_content)
                
            print(f"[+] ¡Archivo recuperado en {dest}! Verifica si el contenido es válido (si estaba fragmentado, el contenido podría estar corrupto).")
                
        except ValueError:
            print("Uso: recover <id> <ruta_destino>")
        except Exception as e:
            print(f"Error al recuperar archivo: {e}")

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
        """Realiza File Carving automatizado buscando Magic Bytes en la partición. Uso: carve <directorio_destino> [tipos...]

        Ejemplos:
          carve ./recuperados            → busca todos los tipos soportados
          carve ./recuperados jpg pdf    → busca solo JPEG y PDF

        Tipos soportados: jpg, png, pdf, zip, exe, gif, rar, mp3, db, elf
        """
        if not self.current_parser:
            print(_("Selecciona una partición válida primero."))
            return

        args = arg.split()
        if not args:
            print("Uso: carve <directorio_destino> [tipos...]")
            print("Ejemplo: carve ./recuperados jpg pdf png")
            return

        output_dir = args[0]
        filter_types = [t.lower() for t in args[1:]] if len(args) > 1 else []

        # Filtrar firmas según los tipos solicitados
        if filter_types:
            custom_sigs = [s for s in SIGNATURES if s["ext"].lower() in filter_types]
            if not custom_sigs:
                print(f"[!] Ningún tipo válido reconocido. Tipos disponibles: {', '.join(s['ext'] for s in SIGNATURES)}")
                return
        else:
            custom_sigs = None  # Usar todas las firmas

        # Resumen previo
        sigs_to_use = custom_sigs if custom_sigs else SIGNATURES
        print(f"\n[+] Iniciando File Carving automatizado en la partición {self.selected_partition}...")
        print(f"    Directorio de salida : {output_dir}")
        print(f"    Tipos a buscar       : {', '.join(s['name'] for s in sigs_to_use)}")
        print(f"    Tamaño de partición  : {self.current_parser.partition.size_in_bytes / (1024**2):.2f} MB")
        print("    Esto puede tardar varios minutos en particiones grandes.")
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
                partition=self.current_parser.partition,
                output_dir=output_dir,
                progress_cb=progress,
                custom_signatures=custom_sigs,
            )
            results = carver.carve()

            sys.stdout.write("\n")
            print(f"\n[+] Carving finalizado.")
            print(f"    Archivos recuperados : {len(results)}")
            print(f"    Saltados / errores   : {carver.skipped_count}")

            if results:
                print(f"\n    {'#':<6} | {'Tipo':<22} | {'Offset':<14} | {'Tamaño':<12} | {'Footer':<8} | Nombre")
                print("    " + "-" * 90)
                for r in results:
                    footer_ok = "✓" if r["footer_found"] else "(truncado)"
                    size_kb   = r["size"] / 1024
                    print(f"    {r['index']:<6} | {r['type']:<22} | {hex(r['abs_offset']):<14} | {size_kb:>8.1f} KB | {footer_ok:<10} | {r['filename']}")
                print(f"\n    Todos los archivos se guardaron en: {output_dir}")
            else:
                print("    No se encontraron archivos con las firmas especificadas.")

        except Exception as e:
            sys.stdout.write("\n")
            print(f"[!] Error durante el carving: {e}")



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
