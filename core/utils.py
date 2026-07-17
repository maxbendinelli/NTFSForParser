import datetime

def hexdump(src: bytes, offset: int = 0, length: int = 16) -> str:
    """
    Genera un volcado hexadecimal clásico coloreando firmas críticas.
    Ideal para mostrar a los alumnos las firmas estructurales y magic bytes.
    """
    if not src:
        return ""
        
    # Definir colores ANSI
    COLOR_RESET = "\033[0m"
    COLOR_GREEN = "\033[32m"   # File systems y firmas de VBR correctas
    COLOR_YELLOW = "\033[33m"  # Estructuras de sistemas de archivos (FILE, INDX, 55AA)
    COLOR_CYAN = "\033[36m"    # Magic bytes de archivos comunes (PNG, JPEG, PDF, ZIP, EXE)
    COLOR_RED = "\033[31m"     # BitLocker, BAAD o anomalías
    COLOR_BOLD = "\033[1m"
    
    # Crear un mapa de colores por cada byte
    colors = [None] * len(src)
    
    i = 0
    while i < len(src):
        abs_pos = offset + i
        
        # 1. Cabecera VBR / MBR firma 55AA
        if abs_pos % 512 == 510 and i + 1 < len(src) and src[i:i+2] == b'\x55\xAA':
            colors[i] = COLOR_YELLOW + COLOR_BOLD
            colors[i+1] = COLOR_YELLOW + COLOR_BOLD
            i += 2
            continue
            
        # 2. Firmas de boot sector (VBR) en el offset 3 de la partición (o sector)
        if abs_pos % 512 == 3 and i + 8 <= len(src):
            sig = src[i:i+8]
            if sig == b'NTFS    ' or sig == b'EXFAT   ':
                for k in range(8):
                    colors[i+k] = COLOR_GREEN + COLOR_BOLD
                i += 8
                continue
            elif sig == b'-FVE-FS-':
                for k in range(8):
                    colors[i+k] = COLOR_RED + COLOR_BOLD
                i += 8
                continue
            elif sig in (b'MSWIN4.1', b'MSDOS5.0'):
                for k in range(8):
                    colors[i+k] = COLOR_GREEN + COLOR_BOLD
                i += 8
                continue
                
        # 3. Estructuras lógicas NTFS (FILE, INDX, BAAD)
        if abs_pos % 512 == 0 and i + 4 <= len(src):
            sig4 = src[i:i+4]
            if sig4 == b'FILE':
                for k in range(4):
                    colors[i+k] = COLOR_YELLOW + COLOR_BOLD
                i += 4
                continue
            elif sig4 == b'INDX':
                for k in range(4):
                    colors[i+k] = COLOR_YELLOW + COLOR_BOLD
                i += 4
                continue
            elif sig4 == b'BAAD':
                for k in range(4):
                    colors[i+k] = COLOR_RED + COLOR_BOLD
                i += 4
                continue
                
        # 4. Cabeceras mágicas de archivos (PNG, PDF, ZIP, RAR, EXE)
        if i + 4 <= len(src):
            sig4 = src[i:i+4]
            if sig4 == b'\x89PNG' or sig4 == b'%PDF' or sig4 == b'PK\x03\x04':
                for k in range(4):
                    colors[i+k] = COLOR_CYAN + COLOR_BOLD
                i += 4
                continue
            elif sig4 == b'MZ\x90\x00' or sig4 == b'\x7fELF':
                for k in range(4):
                    colors[i+k] = COLOR_CYAN + COLOR_BOLD
                i += 4
                continue
                
        if i + 3 <= len(src):
            sig3 = src[i:i+3]
            if sig3 == b'\xFF\xD8\xFF':
                for k in range(3):
                    colors[i+k] = COLOR_CYAN + COLOR_BOLD
                i += 3
                continue
                
        if i + 2 <= len(src):
            sig2 = src[i:i+2]
            if sig2 == b'MZ':
                for k in range(2):
                    colors[i+k] = COLOR_CYAN + COLOR_BOLD
                i += 2
                continue
                
        i += 1

    # Construir volcado
    result = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        chunk_colors = colors[i:i+length]
        
        # Formatear hexadecimal
        hex_parts = []
        for idx, x in enumerate(chunk):
            color = chunk_colors[idx]
            if color:
                hex_parts.append(f"{color}{x:02X}{COLOR_RESET}")
            else:
                hex_parts.append(f"{x:02X}")
                
        # Espaciado extra estilo xxd a los 8 bytes
        if len(hex_parts) > 8:
            hexa = ' '.join(hex_parts[:8]) + '  ' + ' '.join(hex_parts[8:])
        else:
            hexa = ' '.join(hex_parts)
            
        # Relleno de alineación para la columna ASCII
        if len(chunk) < length:
            missing = length - len(chunk)
            spaces = missing * 3
            if len(chunk) <= 8 and length > 8:
                spaces += 1
            hexa += ' ' * spaces
            
        # Formatear representación ASCII
        text_parts = []
        for idx, x in enumerate(chunk):
            color = chunk_colors[idx]
            char_repr = chr(x) if 0x20 <= x < 0x7F else '.'
            if color:
                text_parts.append(f"{color}{char_repr}{COLOR_RESET}")
            else:
                text_parts.append(char_repr)
        text = ''.join(text_parts)
        
        result.append(f"{offset + i:08X}  {hexa}  |{text}|")
        
    return '\n'.join(result)

def print_breakdown(name: str, raw_bytes: bytes, parsed_value: any, description: str = ""):
    """
    Función didáctica para mostrar qué bytes se usaron para obtener qué valor.
    """
    hexa = ' '.join([f"{x:02X}" for x in raw_bytes])
    print(f"    > {name}:")
    print(f"      Bytes en disco: [{hexa}]")
    print(f"      Valor parseado: {parsed_value} {description}")

def parse_dos_time(date_val: int, time_val: int) -> str:
    """Convierte fecha y hora en formato MS-DOS a una cadena legible."""
    if date_val == 0 and time_val == 0:
        return "N/A"
        
    year = ((date_val >> 9) & 0x7F) + 1980
    month = (date_val >> 5) & 0x0F
    day = date_val & 0x1F
    
    hour = (time_val >> 11) & 0x1F
    minute = (time_val >> 5) & 0x3F
    second = (time_val & 0x1F) * 2
    
    try:
        dt = datetime.datetime(year, month, day, hour, minute, second)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "Fecha Inválida"

def parse_filetime(filetime: int) -> str:
    """Convierte un timestamp FILETIME de Windows (100-ns desde 1601) a cadena."""
    if filetime == 0:
        return "N/A"
    
    unix_time = (filetime / 10000000) - 11644473600
    try:
        dt = datetime.datetime.fromtimestamp(unix_time)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return "Fecha Inválida"
