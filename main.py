import sys
import os
import re
from core.data_source import RawImageSource, E01ImageSource, SplitRawImageSource
from core.partition_manager import MBRParser
from fs.ntfs_parser import NTFSParser
from fs.fat_parser import FATParser
from core.shell import NTFSShell
from core.utils import hexdump, print_breakdown

import argparse
from core.i18n import set_language, _

# Forzar codificacion UTF-8 de forma segura para compatibilidad multiplataforma
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="NTFSForParser - Framework Educativo Forense")
    parser.add_argument("image_path", nargs="?", default=None, help="Ruta a la imagen (.dd, .001, .e01) o dispositivo físico (\\\\.\\PhysicalDrive0)")
    parser.add_argument("--partitions", action="store_true", help="Lista las particiones encontradas y sale")
    parser.add_argument("--sector", type=int, help="Muestra el volcado del sector físico especificado (LBA absoluto)")
    parser.add_argument("--cluster", type=int, help="Muestra el volcado del clúster lógico especificado (requiere --part)")
    parser.add_argument("--identify-sector", type=int, help="Aplica Magic Bytes a un sector físico")
    parser.add_argument("--identify-cluster", type=int, help="Aplica Magic Bytes a un clúster lógico (requiere --part)")
    parser.add_argument("--runs", type=str, help="Imprime los Data Runs, Cadena FAT o Bloques Ext4 de un archivo (requiere --part). Usa ID o nombre.")
    parser.add_argument("--dump-clusters", nargs=3, metavar=('START', 'END_OR_COUNT', 'DEST'), help="Vuelca un rango de clústeres/bloques a disco (requiere --part). Ej: --dump-clusters 100 +50 out.bin")
    parser.add_argument("--part", type=int, help="Índice de la partición para comandos lógicos")
    parser.add_argument("--count", type=int, default=1, help="Cantidad de sectores/clústeres continuos a procesar")
    parser.add_argument("--carve", type=str, metavar='DEST_DIR', help="Realiza carving de archivos en la partición (requiere --part) o en todo el disco si no se especifica --part")
    parser.add_argument("--types", type=str, help="Filtra tipos de archivos a buscar (separados por comas, ej: jpg,png)")
    parser.add_argument("--max-size", type=str, help="Sobrescribe el tamaño máximo de carving (ej: 50MB, 2048KB)")
    parser.add_argument("--lang", type=str, default="es", choices=["es", "en"], help="Idioma de la interfaz (es, en)")
    
    args = parser.parse_args()
    
    set_language(args.lang)
    image_path = args.image_path

    # Si no se provee imagen forense
    if image_path is None:
        # Si se solicitan comandos CLI que requieren obligatoriamente imagen
        if (args.partitions or args.sector is not None or args.cluster is not None or
            args.identify_sector is not None or args.identify_cluster is not None or
            args.runs is not None or args.dump_clusters is not None or args.carve is not None):
            print(_("Error: Los comandos por línea de comandos (CLI) requieren especificar una imagen forense."))
            sys.exit(1)
            
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
        print(_(" v1.0.0 - Framework Educativo de Informática Forense | Por: Max Bendinelli"))
        print("==========================================================================")
        print(_("\n[!] Advertencia: No se ha especificado ninguna imagen forense."))
        print(_("    Por favor, usa el comando 'open <ruta_imagen>' para cargar una.\n"))
        
        if sys.platform == "win32":
            try:
                import readline
            except ImportError:
                print(_("[i] Nota didáctica: Para habilitar el autocompletado interactivo con la tecla <Tab> en Windows, instalá:"))
                print("    pip install pyreadline3\n")
        
        shell = NTFSShell(None, None)
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print("\nSaliendo...")
        return

    if not os.path.exists(image_path) and not image_path.startswith(r"\\.\PhysicalDrive"):
        print(_("Error: El archivo {image_path} no existe.").format(image_path=image_path))
        sys.exit(1)

    try:
        if not (args.partitions or args.sector is not None or args.cluster is not None or args.identify_sector is not None or args.identify_cluster is not None):
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
            print(_(" v1.0.0 - Framework Educativo de Informática Forense | Por: Max Bendinelli"))
            print("==========================================================================")
            print(_("\n[+] Cargando fuente de datos: {image_path}").format(image_path=image_path))
            
        # 1. Determinar tipo de fuente de datos
        if re.search(r'\.[0-9]{3}$', image_path.lower()):
            data_source = SplitRawImageSource(image_path)
        elif image_path.lower().endswith('.e01'):
            data_source = E01ImageSource(image_path)
        else:
            data_source = RawImageSource(image_path)
            
        # 2. Capa de Particiones
        mbr_parser = MBRParser(data_source)
        
        # Ejecución CLI directa
        if args.partitions:
            shell = NTFSShell(data_source, mbr_parser)
            shell.do_partitions("")
            return
            
        if args.sector is not None:
            offset = args.sector * 512
            size = args.count * 512
            print(_("\n[+] Volcado del Sector Físico {sector} (Offset: {offset}, Tamaño: {size} bytes)").format(sector=args.sector, offset=hex(offset), size=size))
            data = data_source.read(offset, size)
            print(hexdump(data, offset=offset))
            return
            
        if args.identify_sector is not None:
            shell = NTFSShell(data_source, mbr_parser)
            for i in range(args.count):
                sector_num = args.identify_sector + i
                shell.do_identify(f"sector {sector_num}")
            return
            
        if args.cluster is not None or args.identify_cluster is not None:
            if args.part is None:
                print(_("Error: Los comandos lógicos (--cluster, --identify-cluster) requieren indicar la partición con --part <indice>"))
                return
            
            shell = NTFSShell(data_source, mbr_parser)
            shell.do_select(str(args.part))
            
            if not shell.current_parser:
                print(_("Error: Partición no inicializable."))
                return
                
            if args.cluster is not None:
                for i in range(args.count):
                    c_num = args.cluster + i
                    offset = shell.current_parser.get_cluster_offset(c_num)
                    bpc = shell.current_parser.get_cluster_size()
                    print(_("\n[+] Volcado del Clúster Lógico {c_num} (Offset: {offset}, Tamaño: {bpc} bytes)").format(c_num=c_num, offset=hex(offset), bpc=bpc))
                    data = data_source.read(offset, bpc)
                    print(hexdump(data, offset=offset))
            
            if args.identify_cluster is not None:
                for i in range(args.count):
                    c_num = args.identify_cluster + i
                    shell.do_identify(f"cluster {c_num}")
                    
            if args.runs is not None:
                shell.do_runs(args.runs)
                
            if args.dump_clusters is not None:
                shell.do_dump_clusters(f"{args.dump_clusters[0]} {args.dump_clusters[1]} {args.dump_clusters[2]}")
                
            return
            
        if args.carve is not None:
            shell = NTFSShell(data_source, mbr_parser)
            if args.part is not None:
                shell.do_select(str(args.part))
            
            carve_cmds = [args.carve]
            if args.types:
                carve_cmds.extend(["--types", args.types])
            if args.max_size:
                carve_cmds.extend(["--max-size", args.max_size])
                
            shell.do_carve(" ".join(carve_cmds))
            return
            
        # Si no hay parámetros especiales, lanzar el Shell Interactivo
        print(_("    Tamaño total: {size:.2f} GB").format(size=data_source.get_size() / (1024**3)))
        print(_("    Se encontraron {count} particiones.").format(count=len(mbr_parser.partitions)))
        shell = NTFSShell(data_source, mbr_parser)
        shell.cmdloop()

    except PermissionError:
        print(_("\n[!] Error de permisos: Si intentas abrir un disco físico, asegúrate de ejecutar el script como Administrador."))
    except Exception as e:
        print(_("\n[!] Error inesperado: {error}").format(error=e))
    finally:
        if 'data_source' in locals():
            data_source.close()

if __name__ == "__main__":
    main()
