"""
fs/carver.py — Módulo de File Carving Automatizado

Escanea clústeres/bloques de una partición en busca de firmas conocidas
(Magic Bytes) y extrae archivos completos detectando sus delimitadores de fin.
Diseñado con un enfoque didáctico para mostrar la técnica de recuperación ciega.
"""

import os
import re
import configparser


# ---------------------------------------------------------------------------
# Tabla de firmas (Magic Bytes)
# Cada entrada: nombre, ext, header, footer, max_size (bytes)
# footer=None → se usa max_size como límite de extracción
#
# Organizada por categorías:
#   - Imágenes
#   - Audio
#   - Vídeo
#   - Documentos Office y texto
#   - Archivos comprimidos
#   - Ejecutables y bibliotecas
#   - Bases de datos y registros
#   - Artefactos forenses (Windows, Linux)
#   - Certificados / Claves criptográficas
#   - Otros formatos populares
# ---------------------------------------------------------------------------
SIGNATURES = [

    # ── Imágenes ───────────────────────────────────────────────────────────
    {
        "name": "JPEG",
        "ext": "jpg",
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "max_size": 15 * 1024 * 1024,
    },
    {
        "name": "PNG",
        "ext": "png",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82",
        "max_size": 30 * 1024 * 1024,
    },
    {
        "name": "GIF",
        "ext": "gif",
        "header": b"GIF8",
        "footer": b"\x00\x3B",
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "BMP",
        "ext": "bmp",
        "header": b"BM",
        "footer": None,
        "max_size": 30 * 1024 * 1024,
    },
    {
        "name": "TIFF (little-endian)",
        "ext": "tif",
        "header": b"II\x2A\x00",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "TIFF (big-endian)",
        "ext": "tif",
        "header": b"MM\x00\x2A",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "WebP",
        "ext": "webp",
        "header": b"RIFF",           # Se refina después con b"WEBP" en offset 8
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "ICO",
        "ext": "ico",
        "header": b"\x00\x00\x01\x00",
        "footer": None,
        "max_size": 1 * 1024 * 1024,
    },
    {
        "name": "PSD (Photoshop)",
        "ext": "psd",
        "header": b"8BPS",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },

    # ── Audio ──────────────────────────────────────────────────────────────
    {
        "name": "MP3 (ID3 tag)",
        "ext": "mp3",
        "header": b"ID3",
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "MP3 (sin tag)",
        "ext": "mp3",
        "header": b"\xFF\xFB",
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "WAV / AVI (RIFF)",
        "ext": "wav",
        "header": b"RIFF",
        "footer": None,
        "max_size": 300 * 1024 * 1024,
    },
    {
        "name": "FLAC",
        "ext": "flac",
        "header": b"fLaC",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "OGG",
        "ext": "ogg",
        "header": b"OggS",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "AAC / M4A (MP4 audio)",
        "ext": "m4a",
        "header": b"\x00\x00\x00\x20ftyp",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "MIDI",
        "ext": "mid",
        "header": b"MThd",
        "footer": None,
        "max_size": 5 * 1024 * 1024,
    },

    # ── Vídeo ──────────────────────────────────────────────────────────────
    {
        "name": "MP4 / MOV (ftyp)",
        "ext": "mp4",
        "header": b"ftyp",
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,  # 2 GB
    },
    {
        "name": "AVI",
        "ext": "avi",
        "header": b"RIFF",
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
    },
    {
        "name": "FLV",
        "ext": "flv",
        "header": b"FLV\x01",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "MKV / WebM (EBML)",
        "ext": "mkv",
        "header": b"\x1A\x45\xDF\xA3",
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
    },
    {
        "name": "MPEG",
        "ext": "mpg",
        "header": b"\x00\x00\x01\xBA",
        "footer": b"\x00\x00\x01\xB9",
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "WMV / WMA (ASF)",
        "ext": "wmv",
        "header": b"\x30\x26\xB2\x75\x8E\x66\xCF\x11",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },

    # ── Documentos Office y texto ──────────────────────────────────────────
    {
        "name": "PDF",
        "ext": "pdf",
        "header": b"%PDF",
        "footer": b"%%EOF",
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Office OpenXML (DOCX/XLSX/PPTX)",
        "ext": "docx",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "DOC / XLS / PPT (OLE2)",
        "ext": "doc",
        "header": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "RTF",
        "ext": "rtf",
        "header": b"{\\rtf",
        "footer": b"}",
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "XML",
        "ext": "xml",
        "header": b"<?xml",
        "footer": None,
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "HTML",
        "ext": "html",
        "header": b"<!DOCTYPE html",
        "footer": b"</html>",
        "max_size": 5 * 1024 * 1024,
    },
    {
        "name": "ODF (ODT/ODS/ODP)",
        "ext": "odt",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "max_size": 50 * 1024 * 1024,
    },

    # ── Archivos comprimidos ───────────────────────────────────────────────
    {
        "name": "ZIP",
        "ext": "zip",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "RAR (v4)",
        "ext": "rar",
        "header": b"Rar!\x1A\x07\x00",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "RAR (v5)",
        "ext": "rar",
        "header": b"Rar!\x1A\x07\x01\x00",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "7-Zip",
        "ext": "7z",
        "header": b"7z\xBC\xAF\x27\x1C",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "GZIP",
        "ext": "gz",
        "header": b"\x1F\x8B\x08",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "BZIP2",
        "ext": "bz2",
        "header": b"BZh",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "XZ / LZMA",
        "ext": "xz",
        "header": b"\xFD7zXZ\x00",
        "footer": b"\x00\x00",
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "TAR",
        "ext": "tar",
        "header": b"ustar",
        "footer": None,
        "max_size": 1024 * 1024 * 1024,
    },
    {
        "name": "ISO 9660 (imagen CD/DVD)",
        "ext": "iso",
        "header": b"\x00CD001",
        "footer": None,
        "max_size": 700 * 1024 * 1024,
    },
    {
        "name": "VMDK (VMware disco)",
        "ext": "vmdk",
        "header": b"KDMV",
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
    },

    # ── Ejecutables y bibliotecas ──────────────────────────────────────────
    {
        "name": "EXE / DLL (PE Windows)",
        "ext": "exe",
        "header": b"MZ",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "ELF (Linux/Unix Binary)",
        "ext": "elf",
        "header": b"\x7fELF",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Mach-O (macOS Binary)",
        "ext": "macho",
        "header": b"\xCE\xFA\xED\xFE",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Mach-O 64-bit (macOS)",
        "ext": "macho",
        "header": b"\xCF\xFA\xED\xFE",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Java CLASS",
        "ext": "class",
        "header": b"\xCA\xFE\xBA\xBE",
        "footer": None,
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "Python bytecode (.pyc)",
        "ext": "pyc",
        "header": b"\x55\x0D\x0D\x0A",    # Python 3.8+
        "footer": None,
        "max_size": 5 * 1024 * 1024,
    },
    {
        "name": "WebAssembly (.wasm)",
        "ext": "wasm",
        "header": b"\x00asm",
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },

    # ── Bases de datos y registros ─────────────────────────────────────────
    {
        "name": "SQLite DB",
        "ext": "db",
        "header": b"SQLite format 3\x00",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "Windows Registry Hive",
        "ext": "hive",
        "header": b"regf",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "Windows Event Log (EVT)",
        "ext": "evt",
        "header": b"LfLe",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "Windows Event Log (EVTX)",
        "ext": "evtx",
        "header": b"ElfFile\x00",
        "footer": None,
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "Windows Prefetch (.pf)",
        "ext": "pf",
        "header": b"SCCA",
        "footer": None,
        "max_size": 1 * 1024 * 1024,
    },
    {
        "name": "Windows LNK (Shortcut)",
        "ext": "lnk",
        "header": b"\x4C\x00\x00\x00\x01\x14\x02\x00",
        "footer": None,
        "max_size": 2 * 1024 * 1024,
    },
    {
        "name": "Windows Thumbs.db (OLE2)",
        "ext": "db",
        "header": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        "footer": None,
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "Crash Dump / Minidump",
        "ext": "dmp",
        "header": b"MDMP",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "Windows Recycle Bin ($I)",
        "ext": "ri",
        "header": b"\x01\x00\x00\x00\x00\x00\x00\x00",
        "footer": None,
        "max_size": 1 * 1024 * 1024,
    },

    # ── Artefactos forenses / imágenes de disco ────────────────────────────
    {
        "name": "PCAP (captura de red)",
        "ext": "pcap",
        "header": b"\xD4\xC3\xB2\xA1",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "PCAPng (captura de red v2)",
        "ext": "pcapng",
        "header": b"\x0A\x0D\x0D\x0A",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },

    # ── Certificados y criptografía ────────────────────────────────────────
    {
        "name": "X.509 Certificate (DER)",
        "ext": "cer",
        "header": b"\x30\x82",
        "footer": None,
        "max_size": 1 * 1024 * 1024,
    },
    {
        "name": "PEM Certificate / Key",
        "ext": "pem",
        "header": b"-----BEGIN",
        "footer": b"-----END",
        "max_size": 1 * 1024 * 1024,
    },
    {
        "name": "PGP / GPG (mensaje)",
        "ext": "pgp",
        "header": b"-----BEGIN PGP",
        "footer": b"-----END PGP",
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "Bitcoin Wallet",
        "ext": "wallet",
        "header": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00",
        "footer": None,
        "max_size": 10 * 1024 * 1024,
    },

    # ── Fuentes tipográficas ───────────────────────────────────────────────
    {
        "name": "TrueType Font (TTF)",
        "ext": "ttf",
        "header": b"\x00\x01\x00\x00\x00",
        "footer": None,
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "WOFF Font",
        "ext": "woff",
        "header": b"wOFF",
        "footer": None,
        "max_size": 5 * 1024 * 1024,
    },

    # ── Otros formatos populares ───────────────────────────────────────────
    {
        "name": "Java Archive (JAR)",
        "ext": "jar",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "max_size": 200 * 1024 * 1024,
    },
    {
        "name": "Android APK",
        "ext": "apk",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "Torrent",
        "ext": "torrent",
        "header": b"d8:announce",
        "footer": b"ee",
        "max_size": 2 * 1024 * 1024,
    },
    {
        "name": "Email (EML)",
        "ext": "eml",
        "header": b"From ",
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "Email (Outlook MSG)",
        "ext": "msg",
        "header": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Outlook PST / OST",
        "ext": "pst",
        "header": b"!BDN",
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
    },
    {
        "name": "Firefox / Chrome Cookie DB",
        "ext": "db",
        "header": b"SQLite format 3\x00",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Chrome History (LevelDB LLOG)",
        "ext": "log",
        "header": b"\xEF\xBF\xBD\xEF\xBF\xBD",
        "footer": None,
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "Thumbcache (Windows)",
        "ext": "db",
        "header": b"CMMM",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "Flash SWF",
        "ext": "swf",
        "header": b"CWS",
        "footer": None,
        "max_size": 30 * 1024 * 1024,
    },
    {
        "name": "Flash SWF (uncompressed)",
        "ext": "swf",
        "header": b"FWS",
        "footer": None,
        "max_size": 30 * 1024 * 1024,
    },
]


def generate_default_signatures_config(config_path="signatures.conf"):
    """Genera el archivo signatures.conf con el set de firmas predefinido."""
    config = configparser.ConfigParser()
    for sig in SIGNATURES:
        section_name = sig["name"]
        config[section_name] = {
            "ext": sig["ext"],
            "header": sig["header"].hex(),
            "footer": sig["footer"].hex() if sig["footer"] else "",
            "max_size": str(sig["max_size"])
        }
    with open(config_path, 'w', encoding='utf-8') as f:
        config.write(f)


def load_signatures(config_path="signatures.conf"):
    """Carga firmas desde el archivo signatures.conf. Lo crea si no existe."""
    if not os.path.exists(config_path):
        generate_default_signatures_config(config_path)

    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')
    signatures = []
    for section in config.sections():
        try:
            ext = config.get(section, 'ext').strip()
            header_hex = config.get(section, 'header').strip()
            header = bytes.fromhex(header_hex)

            footer = None
            if config.has_option(section, 'footer'):
                footer_hex = config.get(section, 'footer').strip()
                if footer_hex:
                    footer = bytes.fromhex(footer_hex)

            max_size = 10 * 1024 * 1024  # 10 MB por defecto
            if config.has_option(section, 'max_size'):
                max_size = config.getint(section, 'max_size')

            signatures.append({
                "name": section,
                "ext": ext,
                "header": header,
                "footer": footer,
                "max_size": max_size
            })
        except Exception as e:
            print(f"[!] Advertencia: Error al parsear la firma '{section}' en {config_path}: {e}")

    return signatures


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
    max_size_override : si se especifica, sobrescribe el tamaño máximo de carving para todas las firmas
    """

    CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB
    OVERLAP    =  4 * 1024 * 1024  # 4 MB de solapamiento entre chunks

    def __init__(self, data_source, partition, output_dir,
                 progress_cb=None, custom_signatures=None, max_size_override=None):
        self.data_source = data_source
        self.partition = partition
        self.output_dir = output_dir
        self.progress_cb = progress_cb or (lambda pct, msg: None)

        raw_sigs = custom_signatures if custom_signatures is not None else load_signatures()

        # Aplicar el override del tamaño máximo de carving si está presente
        self.signatures = []
        for sig in raw_sigs:
            new_sig = sig.copy()
            if max_size_override is not None:
                new_sig["max_size"] = max_size_override
            self.signatures.append(new_sig)

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
