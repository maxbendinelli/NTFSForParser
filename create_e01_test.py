import os
import sys

try:
    import pyewf
except ImportError:
    print("Error: El módulo 'pyewf' (libewf-python) no está instalado o falló al compilar.")
    print("Por favor, asegúrate de haber ejecutado: pip install libewf-python")
    sys.exit(1)

def convert_dd_to_e01(dd_file="test.dd", e01_file="test.e01"):
    if not os.path.exists(dd_file):
        print(f"[!] No se encontró '{dd_file}'. Por favor, corre primero 'create_dummy_image.py'")
        sys.exit(1)
        
    print(f"[*] Convirtiendo la imagen Raw '{dd_file}' al formato contenedor EnCase '{e01_file}'...")
    
    # Crear handle de EWF
    handle = pyewf.handle()
    
    try:
        # Abrir handle en modo escritura pasándole la lista de segmentos (solo 1 aquí)
        handle.open([e01_file], "w")
        
        # Configurar metadatos forenses obligatorios
        handle.set_media_type(pyewf.media_type.FIXED)
        handle.set_media_flags(pyewf.media_flags.PHYSICAL)
        
        # Configurar metadatos del perito
        handle.set_case_number("CASO-EDU-01")
        handle.set_description("Imagen de prueba para NTFSForParser")
        handle.set_examiner_name("Perito Educador")
        handle.set_evidence_number("EV-001")
        handle.set_notes("Generado vía PyEWF para demostrar funcionalidades")
        
        # Leer el archivo .dd y escribirlo en el contenedor E01
        chunk_size = 1024 * 1024 * 2 # 2 MB chunks
        total_written = 0
        
        with open(dd_file, "rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                
                # Escribir el buffer al contenedor
                handle.write_buffer(data)
                total_written += len(data)
                
        print(f"[+] ¡Éxito! Contenedor '{e01_file}' creado con {total_written} bytes empaquetados.")
        
    except Exception as e:
        print(f"[!] Error al generar el E01: {e}")
        
    finally:
        handle.close()

if __name__ == "__main__":
    convert_dd_to_e01()
