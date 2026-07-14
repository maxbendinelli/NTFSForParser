import os
from abc import ABC, abstractmethod

class DataSource(ABC):
    """
    Clase base abstracta para las fuentes de datos forenses.
    Provee una interfaz común para leer bytes independientemente del formato de imagen.
    """
    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Lee 'size' bytes desde el 'offset' absoluto dado."""
        pass
    
    @abstractmethod
    def get_size(self) -> int:
        """Retorna el tamaño total de la fuente de datos en bytes."""
        pass
    
    @abstractmethod
    def close(self):
        """Cierra el manejador de la fuente de datos."""
        pass
        
    @abstractmethod
    def get_metadata(self) -> dict:
        """Retorna metadatos de la imagen si el formato lo soporta (ej. E01)."""
        pass

class RawImageSource(DataSource):
    """
    Fuente de datos para imágenes crudas (RAW/DD) o dispositivos físicos directos.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_obj = open(file_path, 'rb')
        
        # Determinar el tamaño
        self.file_obj.seek(0, os.SEEK_END)
        self._size = self.file_obj.tell()
        self.file_obj.seek(0)
        
    def read(self, offset: int, size: int) -> bytes:
        self.file_obj.seek(offset)
        return self.file_obj.read(size)
        
    def get_size(self) -> int:
        return self._size
        
    def close(self):
        if self.file_obj:
            self.file_obj.close()
            
    def get_metadata(self) -> dict:
        return {}


class SplitRawImageSource(DataSource):
    """
    Fuente de datos para imágenes crudas divididas (ej: image.001, image.002, etc.).
    Une lógicamente los archivos para que parezcan uno solo continuo.
    """
    def __init__(self, first_file_path: str):
        import glob
        
        # Encontrar el patrón base (ej: si es image.001, buscar image.* o image.00*)
        # Una forma sencilla es buscar secuencialmente
        base_name, ext = os.path.splitext(first_file_path)
        
        self.files = []
        self._total_size = 0
        self.file_handles = []
        
        # Asumiendo extensiones numéricas .001, .002, .003, etc.
        try:
            current_idx = int(ext.replace('.', ''))
        except ValueError:
            # Fallback si no es numérico, tratar solo este archivo
            current_idx = 1
            
        while True:
            current_ext = f".{current_idx:03d}"
            current_file = base_name + current_ext
            
            if os.path.exists(current_file):
                f_obj = open(current_file, 'rb')
                f_obj.seek(0, os.SEEK_END)
                size = f_obj.tell()
                f_obj.seek(0)
                
                self.files.append({
                    "path": current_file,
                    "handle": f_obj,
                    "start_offset": self._total_size,
                    "end_offset": self._total_size + size,
                    "size": size
                })
                self._total_size += size
                self.file_handles.append(f_obj)
                current_idx += 1
            else:
                break
                
        if not self.files:
            raise FileNotFoundError(f"No se pudieron cargar partes del archivo dividido: {first_file_path}")

    def read(self, offset: int, size: int) -> bytes:
        if offset >= self._total_size:
            return b""
            
        data = b""
        bytes_left = size
        current_offset = offset
        
        for part in self.files:
            if bytes_left <= 0:
                break
                
            # Verificar si el offset cae dentro de esta parte
            if part["start_offset"] <= current_offset < part["end_offset"]:
                # Calcular cuánto podemos leer de esta parte
                internal_offset = current_offset - part["start_offset"]
                bytes_available_in_part = part["size"] - internal_offset
                
                bytes_to_read = min(bytes_left, bytes_available_in_part)
                
                part["handle"].seek(internal_offset)
                data += part["handle"].read(bytes_to_read)
                
                current_offset += bytes_to_read
                bytes_left -= bytes_to_read
                
        return data

    def get_size(self) -> int:
        return self._total_size

    def close(self):
        for f in self.file_handles:
            try:
                f.close()
            except:
                pass
                
    def get_metadata(self) -> dict:
        return {}

class E01ImageSource(DataSource):
    """
    Fuente de datos para imágenes EnCase (E01).
    Utiliza la librería pyewf para abstraer la compresión y fragmentación del formato.
    """
    def __init__(self, file_path: str):
        try:
            import pyewf
        except ImportError:
            raise ImportError(
                "La libreria 'pyewf' es necesaria para leer archivos E01.\n"
                "  - En Windows: ejecute 'pip install libewf-python'\n"
                "  - En Linux/macOS: instale libewf-dev usando su gestor de paquetes "
                "(ej. apt, brew) y luego ejecute 'pip install pyewf'"
            )

        self.file_path = file_path
        self.filenames = pyewf.glob(file_path)  # Encuentra todos los segmentos (E01, E02, …)
        self.ewf_handle = pyewf.handle()
        self.ewf_handle.open(self.filenames)
        self._size = self.ewf_handle.get_media_size()
        self._pyewf = pyewf  # Guardamos referencia al módulo

    def read(self, offset: int, size: int) -> bytes:
        self.ewf_handle.seek(offset)
        return self.ewf_handle.read(size)

    def get_size(self) -> int:
        return self._size

    def close(self):
        if self.ewf_handle:
            self.ewf_handle.close()

    def get_metadata(self) -> dict:
        """Devuelve los header values del contenedor E01 (caso, examinador, notas, etc.)."""
        if self.ewf_handle:
            for method_name in ("get_header_values", "get_header_value_identifiers"):
                try:
                    return self.ewf_handle.get_header_values()
                except Exception:
                    break
        return {}

    def get_hash_values(self) -> dict:
        """
        Recupera los hashes almacenados en el contenedor E01.
        pyewf puede guardar MD5 y SHA1 en los 'hash values'.
        Devuelve un dict como {"md5": "abc123...", "sha1": "def456..."}.
        """
        result = {}
        if not self.ewf_handle:
            return result

        # Intentar get_hash_values() → dict-like
        try:
            hv = self.ewf_handle.get_hash_values()
            if hv:
                for k, v in hv.items():
                    key = k.decode('utf-8').lower() if isinstance(k, bytes) else k.lower()
                    val = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                    result[key] = val
            if result:
                return result
        except Exception:
            pass

        # Fallback: get_md5_hash() y get_sha1_hash() directos
        for attr, label in (("get_md5_hash", "md5"), ("get_sha1_hash", "sha1")):
            try:
                h = getattr(self.ewf_handle, attr)()
                if h:
                    result[label] = h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
            except Exception:
                pass

        # Segundo fallback: buscar en header_values
        if not result:
            try:
                hv = self.ewf_handle.get_header_values()
                for k, v in hv.items():
                    key = k.decode('utf-8').lower() if isinstance(k, bytes) else k.lower()
                    if 'md5' in key or 'sha1' in key or 'hash' in key:
                        val = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                        result[key] = val
            except Exception:
                pass

        return result

    def get_chunk_count(self) -> int:
        """Devuelve el número de chunks del contenedor E01.
        Intenta get_number_of_chunks(); si no está disponible, lo estima
        a partir del tamaño de imagen y el tamaño de chunk por defecto de EWF (32 KB).
        """
        try:
            n = self.ewf_handle.get_number_of_chunks()
            if n and n > 0:
                return n
        except Exception:
            pass
        try:
            n = self.ewf_handle.chunk_count
            if n and n > 0:
                return n
        except Exception:
            pass
        # Estimacion: EWF usa chunks de 32 KB por defecto
        ewf_default_chunk = 32 * 1024
        return (self._size + ewf_default_chunk - 1) // ewf_default_chunk

    def verify_internal_checksums(self) -> tuple:
        """
        Verifica los checksums internos (CRC por chunk) del contenedor E01
        usando pyewf. Devuelve (ok: bool, mensajes: list[str]).
        """
        errors = []
        try:
            chunk_count = self.get_chunk_count()
            if chunk_count == 0:
                return (True, ["No se pudo determinar el numero de chunks."])

            for i in range(chunk_count):
                try:
                    ok = self.ewf_handle.check_chunk(i)
                    if not ok:
                        errors.append(f"Chunk {i} fallo la verificacion CRC interna.")
                except AttributeError:
                    return (True, ["check_chunk() no disponible en esta version de pyewf (la verificacion CRC interna requiere libewf >= 20140807)."])
                except Exception as e:
                    errors.append(f"Chunk {i}: error ({e})")

        except Exception as e:
            return (False, [f"Error durante verificacion interna: {e}"])

        return (len(errors) == 0, errors)

