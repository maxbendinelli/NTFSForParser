import datetime

def hexdump(src: bytes, offset: int = 0, length: int = 16) -> str:
    """
    Genera un volcado hexadecimal clásico estilo xxd.
    Ideal para mostrar a los alumnos los datos en crudo.
    """
    if not src:
        return ""
        
    result = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        
        # Valores hexadecimales
        hexa = ' '.join([f"{x:02X}" for x in chunk])
        # Separar en grupos de 8 bytes para mejor lectura
        if len(chunk) > 8:
            hexa = hexa[:23] + ' ' + hexa[23:]
            
        # Representación ASCII (caracteres imprimibles)
        text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in chunk])
        
        # Formato final: Offset | Hexadecimal | ASCII
        result.append(f"{offset + i:08X}  {hexa:<49}  |{text}|")
        
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
