"""
fs/carver.py — Módulo de File Carving Automatizado

Escanea clústeres/bloques de una partición en busca de firmas conocidas
(Magic Bytes) y extrae archivos completos detectando sus delimitadores de fin.
Diseñado con un enfoque didáctico para mostrar la técnica de recuperación ciega.
"""

import os
import re


# ---------------------------------------------------------------------------
# Tabla de firmas (Magic Bytes)
# Cada entrada: (nombre, header_bytes, footer_bytes, max_size_bytes, extension)
# footer=None → se usa max_size para truncar
# ---------------------------------------------------------------------------
SIGNATURES = [
    {
        "name": "JPEG",
        "ext": "jpg",
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "max_size": 15 * 1024 * 1024,   # 15 MB
    },
    {
        "name": "PNG",
        "ext": "png",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82",
        "max_size": 30 * 1024 * 1024,   # 30 MB
    },
    {
        "name": "PDF",
        "ext": "pdf",
        "header": b"%PDF",
        "footer": b"%%EOF",
        "max_size": 50 * 1024 * 1024,   # 50 MB
    },
    {
        "name": "ZIP / Office Open XML",
        "ext": "zip",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "max_size": 100 * 1024 * 1024,  # 100 MB
    },
    {
        "name": "EXE / DLL (PE)",
        "ext": "exe",
        "header": b"MZ",
        "footer": None,
        "max_size": 20 * 1024 * 1024,   # 20 MB
    },
    {
        "name": "GIF",
        "ext": "gif",
        "header": b"GIF8",
        "footer": b"\x00\x3B",
        "max_size": 10 * 1024 * 1024,   # 10 MB
    },
    {
        "name": "RAR",
        "ext": "rar",
        "header": b"Rar!\x1A\x07",
        "footer": None,
        "max_size": 100 * 1024 * 1024,  # 100 MB
    },
    {
        "name": "MP3",
        "ext": "mp3",
        "header": b"ID3",
        "footer": None,
        "max_size": 20 * 1024 * 1024,   # 20 MB
    },
    {
        "name": "SQLite DB",
        "ext": "db",
        "header": b"SQLite format 3\x00",
        "footer": None,
        "max_size": 50 * 1024 * 1024,   # 50 MB
    },
    {
        "name": "ELF (Linux Binary)",
        "ext": "elf",
        "header": b"\x7fELF",
        "footer": None,
        "max_size": 50 * 1024 * 1024,   # 50 MB
    },
]


class FileCarver:
    """
    Realiza File Carving ciego sobre los datos crudos de una partición.

    Parámetros
    ----------
    data_source  : objeto DataSource con método read(offset, size)
    partition    : objeto de partición con start_offset y size_in_bytes
    output_dir   : directorio donde se guardarán los archivos recuperados
    chunk_size   : tamaño del chunk de lectura (16 MB por defecto)
    progress_cb  : callback(percent, status_str) para actualizar la UI
    """

    CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB
    OVERLAP    =  4 * 1024 * 1024  # 4 MB de solapamiento entre chunks

    def __init__(self, data_source, partition, output_dir,
                 progress_cb=None, custom_signatures=None):
        self.data_source = data_source
        self.partition = partition
        self.output_dir = output_dir
        self.progress_cb = progress_cb or (lambda pct, msg: None)

        self.signatures = custom_signatures if custom_signatures is not None else SIGNATURES

        # Precompilar headers como patrones de bytes para búsqueda rápida
        self._compiled = [
            {**sig, "_re": re.compile(re.escape(sig["header"]))}
            for sig in self.signatures
        ]

        os.makedirs(output_dir, exist_ok=True)

        # Contadores
        self.carved_count = 0
        self.skipped_count = 0

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def carve(self):
        """
        Recorre toda la partición en busca de firmas y extrae los archivos.
        Devuelve una lista de dicts con información sobre cada archivo recuperado.
        """
        results = []
        start  = self.partition.start_offset
        end    = start + self.partition.size_in_bytes
        total  = self.partition.size_in_bytes

        offset     = start
        bytes_read = 0

        while offset < end:
            read_size = min(self.CHUNK_SIZE + self.OVERLAP, end - offset)
            chunk = self.data_source.read(offset, read_size)
            if not chunk:
                break

            chunk_results = self._scan_chunk(chunk, offset, end)
            results.extend(chunk_results)

            # Avanzar sin contar el overlap (se relee en el próximo chunk)
            step        = min(self.CHUNK_SIZE, end - offset)
            offset     += step
            bytes_read += step

            pct = int(bytes_read / total * 100)
            self.progress_cb(pct, f"Archivos recuperados: {self.carved_count}")

        self.progress_cb(100, f"Carving finalizado. Recuperados: {self.carved_count}")
        return results

    # ------------------------------------------------------------------
    # Lógica interna
    # ------------------------------------------------------------------

    def _scan_chunk(self, chunk: bytes, chunk_offset: int, end_abs: int) -> list:
        """Busca todas las firmas en el chunk y extrae los archivos encontrados."""
        results = []

        for sig in self._compiled:
            for m in sig["_re"].finditer(chunk):
                hit_pos_in_chunk = m.start()

                # Si el hit está en la zona de overlap del chunk anterior, saltarlo
                # (ya fue procesado en la iteración anterior, salvo en el primer chunk)
                if hit_pos_in_chunk >= self.CHUNK_SIZE and (chunk_offset + self.CHUNK_SIZE < end_abs):
                    continue

                abs_offset = chunk_offset + hit_pos_in_chunk

                result = self._extract_file(sig, chunk, hit_pos_in_chunk,
                                            abs_offset, end_abs)
                if result:
                    results.append(result)
                    self.carved_count += 1

        return results

    def _extract_file(self, sig: dict, chunk: bytes, pos_in_chunk: int,
                      abs_offset: int, end_abs: int):
        """
        Extrae un archivo comenzando en abs_offset.
        Lee más data del disco si el archivo supera el chunk actual.
        """
        max_size = sig["max_size"]

        # Leer toda la data necesaria (puede superar el chunk actual)
        remaining = min(max_size, end_abs - abs_offset)
        if remaining <= 0:
            self.skipped_count += 1
            return None

        # Primero intentar usar el chunk en memoria, extendiendo si hace falta
        available_in_chunk = len(chunk) - pos_in_chunk
        if available_in_chunk >= remaining:
            raw = chunk[pos_in_chunk: pos_in_chunk + remaining]
        else:
            raw = bytearray(chunk[pos_in_chunk:])
            still_needed = remaining - len(raw)
            extra = self.data_source.read(abs_offset + len(raw), still_needed)
            if extra:
                raw.extend(extra)
            raw = bytes(raw)

        # Determinar el fin del archivo
        if sig["footer"] is not None:
            footer_pos = raw.find(sig["footer"])
            if footer_pos != -1:
                file_data = raw[:footer_pos + len(sig["footer"])]
            else:
                # Footer no encontrado dentro del max_size: datos truncados
                file_data = raw
        else:
            file_data = raw

        if not file_data:
            self.skipped_count += 1
            return None

        # Construir nombre del archivo de salida
        filename = (
            f"carved_{self.carved_count:04d}_{sig['ext'].upper()}_"
            f"offset_{hex(abs_offset)}.{sig['ext']}"
        )
        dest_path = os.path.join(self.output_dir, filename)

        try:
            with open(dest_path, "wb") as f:
                f.write(file_data)
        except OSError:
            self.skipped_count += 1
            return None

        return {
            "index":        self.carved_count,
            "type":         sig["name"],
            "ext":          sig["ext"],
            "abs_offset":   abs_offset,
            "size":         len(file_data),
            "filename":     filename,
            "dest":         dest_path,
            "footer_found": sig["footer"] is not None and raw.find(sig["footer"]) != -1,
        }
