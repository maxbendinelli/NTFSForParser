import struct
from core.data_source import DataSource
from core.partition_manager import Partition
from core.utils import parse_filetime

class NTFSVBRParser:
    """
    Analizador del Volume Boot Record (VBR) de NTFS.
    El VBR es el primer sector de una partición NTFS y contiene
    metadatos críticos como el tamaño del clúster y la ubicación de la MFT.
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.bytes_per_sector = 0
        self.sectors_per_cluster = 0
        self.mft_start_cluster = 0
        self.mft_mirror_start_cluster = 0
        self.clusters_per_mft_record = 0
        self.bytes_per_cluster = 0
        
        self._parse_vbr()

    def _parse_vbr(self):
        # El VBR está en el primer sector de la partición
        self.raw_vbr = self.data_source.read(self.partition.start_offset, 512)
        
        # Validar firma NTFS ("NTFS    ") en el offset 3
        oem_id = self.raw_vbr[3:11]
        if oem_id != b'NTFS    ':
            raise ValueError(f"No es una partición NTFS válida. OEM ID: {oem_id}")

        # Estructura del BIOS Parameter Block (BPB) en NTFS
        # Offset 11 (2 bytes): Bytes por sector
        # Offset 13 (1 byte) : Sectores por clúster
        # Offset 48 (8 bytes): Clúster lógico de inicio de la $MFT
        # Offset 56 (8 bytes): Clúster lógico de inicio de la $MFTMirr
        # Offset 64 (1 byte) : Clústeres por registro MFT (o bytes si es negativo)

        self.bytes_per_sector = struct.unpack('<H', self.raw_vbr[11:13])[0]
        self.sectors_per_cluster = struct.unpack('<B', self.raw_vbr[13:14])[0]
        self.bytes_per_cluster = self.bytes_per_sector * self.sectors_per_cluster
        
        self.mft_start_cluster = struct.unpack('<Q', self.raw_vbr[48:56])[0]
        self.mft_mirror_start_cluster = struct.unpack('<Q', self.raw_vbr[56:64])[0]
        
        # Clústeres por registro MFT (si es un valor positivo, indica clústeres.
        # Si es negativo, representa 2^|x| bytes).
        raw_clusters_per_mft_record = struct.unpack('<b', self.raw_vbr[64:65])[0]
        if raw_clusters_per_mft_record < 0:
            self.bytes_per_mft_record = 2 ** abs(raw_clusters_per_mft_record)
        else:
            self.bytes_per_mft_record = raw_clusters_per_mft_record * self.bytes_per_cluster

    def get_mft_offset(self) -> int:
        """Calcula el offset absoluto en bytes donde comienza la $MFT."""
        mft_relative_offset = self.mft_start_cluster * self.bytes_per_cluster
        return self.partition.start_offset + mft_relative_offset

class NTFSParser:
    """
    Clase principal para analizar un sistema de archivos NTFS.
    Integra el parser del VBR y servirá como base para leer la MFT.
    """
    def __init__(self, data_source: DataSource, partition: Partition):
        self.data_source = data_source
        self.partition = partition
        self.vbr = NTFSVBRParser(data_source, partition)
        
    def get_info(self) -> dict:
        return {
            "Bytes por sector": self.vbr.bytes_per_sector,
            "Sectores por clúster": self.vbr.sectors_per_cluster,
            "Bytes por clúster": self.vbr.bytes_per_cluster,
            "Inicio de $MFT (Clúster)": self.vbr.mft_start_cluster,
            "Inicio de $MFT (Offset absoluto)": hex(self.vbr.get_mft_offset()),
            "Bytes por registro MFT": self.vbr.bytes_per_mft_record
        }

    def get_cluster_offset(self, cluster_num: int) -> int:
        """Calcula el offset absoluto de un clúster en NTFS."""
        return self.partition.start_offset + (cluster_num * self.get_cluster_size())

    def get_cluster_size(self) -> int:
        return self.vbr.bytes_per_cluster

    def get_mft_record(self, index: int) -> MFTRecord:
        """Lee un registro de la MFT por su índice asumiendo contigüidad inicial."""
        mft_start_offset = self.vbr.get_mft_offset()
        record_size = self.vbr.bytes_per_mft_record
        
        # OJO: Asume que la MFT no está fragmentada, lo cual es cierto para los primeros registros (ej. Root Dir = 5)
        record_offset = mft_start_offset + (index * record_size)
        raw_data = self.data_source.read(record_offset, record_size)
        
        return MFTRecord(raw_data)

    def read_data_runs(self, data_runs: list, total_size: int) -> bytes:
        """Ensambla el contenido de un archivo leyendo todos sus Data Runs del disco físico."""
        data_buffer = bytearray()
        for run in data_runs:
            if run["start_cluster"] == 0 and run["length"] > 0:
                # Sparse file run (relleno de ceros)
                data_buffer.extend(b'\x00' * (run["length"] * self.get_cluster_size()))
            else:
                offset = self.get_cluster_offset(run["start_cluster"])
                fragment = self.data_source.read(offset, run["length"] * self.get_cluster_size())
                data_buffer.extend(fragment)
                
        # Cortar el padding de sectores para devolver el tamaño exacto del archivo
        return bytes(data_buffer[:total_size])




class MFTRecord:
    """
    Plantilla base para analizar un registro individual de la Master File Table (MFT).
    """
    def __init__(self, record_data: bytes):
        self.raw_data = record_data
        self.signature = ""
        self.sequence_number = 0
        self.link_count = 0
        self.first_attribute_offset = 0
        self.flags = 0
        
        # Validar tamaño mínimo de cabecera FILE
        if len(self.raw_data) >= 42:
            self._parse_header()
            
    def _parse_header(self):
        """
        Analiza la cabecera del registro FILE.
        Estructura típica:
        Offset 0 (4 bytes): Firma (ej. 'FILE' o 'BAAD')
        Offset 16 (2 bytes): Número de secuencia
        Offset 18 (2 bytes): Link count
        Offset 20 (2 bytes): Offset al primer atributo
        Offset 22 (2 bytes): Flags (0x01 = En uso, 0x02 = Directorio)
        """
        self.signature = self.raw_data[0:4].decode('ascii', errors='ignore')
        
        # Analizar campos básicos de la cabecera FILE
        self.sequence_number = struct.unpack('<H', self.raw_data[16:18])[0]
        self.link_count = struct.unpack('<H', self.raw_data[18:20])[0]
        self.first_attribute_offset = struct.unpack('<H', self.raw_data[20:22])[0]
        self.flags = struct.unpack('<H', self.raw_data[22:24])[0]
        
    def is_directory(self) -> bool:
        return (self.flags & 0x02) != 0
        
    def is_in_use(self) -> bool:
        return (self.flags & 0x01) != 0

    def parse_attributes(self):
        """
        Itera sobre los atributos a partir de `first_attribute_offset`.
        """
        self.attributes = []
        self.file_name = ""
        
        # Flujos de datos (Soporte para ADS)
        self.data_streams = [] # Lista de diccionarios con info de cada stream
        
        # Variables de compatibilidad (apuntan al stream principal sin nombre)
        self.data_content = b""
        self.data_runs = []
        self.is_resident_data = True
        self.data_size = 0
        
        self.created = "N/A"
        self.modified = "N/A"
        self.accessed = "N/A"
        self.parent_mft_id = 0
        
        offset = self.first_attribute_offset
        
        while offset < len(self.raw_data):
            attr_type = struct.unpack('<I', self.raw_data[offset:offset+4])[0]
            
            if attr_type == 0xFFFFFFFF: # End of attributes marker
                break
                
            attr_length = struct.unpack('<I', self.raw_data[offset+4:offset+8])[0]
            if attr_length == 0:
                break
                
            non_resident_flag = self.raw_data[offset+8]
            
            # Extraer contenido de atributos de interés
            if non_resident_flag == 0: # Atributo residente
                content_offset = struct.unpack('<H', self.raw_data[offset+20:offset+22])[0]
                content_length = struct.unpack('<I', self.raw_data[offset+16:offset+20])[0]
                
                if attr_type == 0x10: # $STANDARD_INFORMATION
                    std_info_offset = offset + content_offset
                    if content_length >= 32:
                        c_time = struct.unpack('<Q', self.raw_data[std_info_offset:std_info_offset+8])[0]
                        m_time = struct.unpack('<Q', self.raw_data[std_info_offset+8:std_info_offset+16])[0]
                        # mft_time = struct.unpack('<Q', self.raw_data[std_info_offset+16:std_info_offset+24])[0]
                        a_time = struct.unpack('<Q', self.raw_data[std_info_offset+24:std_info_offset+32])[0]
                        
                        self.created = parse_filetime(c_time)
                        self.modified = parse_filetime(m_time)
                        self.accessed = parse_filetime(a_time)
                        
                elif attr_type == 0x30: # $FILE_NAME
                    name_offset = offset + content_offset
                    
                    # File Reference al Directorio Padre (primeros 8 bytes del atributo, 48 bits de MFT ID)
                    parent_ref_bytes = self.raw_data[name_offset : name_offset + 8]
                    if len(parent_ref_bytes) == 8:
                        self.parent_mft_id = struct.unpack('<Q', parent_ref_bytes)[0] & 0x0000FFFFFFFFFFFF
                        
                    name_length_in_chars = self.raw_data[name_offset + 64]
                    name_namespace = self.raw_data[name_offset + 65]
                    
                    # Extraer nombre (Unicode UTF-16LE)
                    name_bytes = self.raw_data[name_offset+66 : name_offset+66+(name_length_in_chars*2)]
                    try:
                        extracted_name = name_bytes.decode('utf-16le')
                        if name_namespace != 2 or not self.file_name: 
                            self.file_name = extracted_name
                    except:
                        pass
                elif attr_type == 0x80: # $DATA
                    # Nombre del flujo (ADS)
                    name_length = self.raw_data[offset+9]
                    name_offset_in_attr = struct.unpack('<H', self.raw_data[offset+10:offset+12])[0]
                    stream_name = ""
                    if name_length > 0:
                        stream_name_bytes = self.raw_data[offset + name_offset_in_attr : offset + name_offset_in_attr + (name_length * 2)]
                        try:
                            stream_name = stream_name_bytes.decode('utf-16le')
                        except:
                            pass

                    data_offset = offset + content_offset
                    content = self.raw_data[data_offset : data_offset + content_length]
                    
                    stream_info = {
                        "name": stream_name,
                        "is_resident": True,
                        "content": content,
                        "runs": [],
                        "size": content_length
                    }
                    self.data_streams.append(stream_info)
                    
                    if not stream_name: # Flujo principal
                        self.data_content = content
                        self.is_resident_data = True
                        self.data_size = content_length
                    
            else: # Atributo No Residente
                if attr_type == 0x80: # $DATA No Residente (Data Runs)
                    name_length = self.raw_data[offset+9]
                    name_offset_in_attr = struct.unpack('<H', self.raw_data[offset+10:offset+12])[0]
                    stream_name = ""
                    if name_length > 0:
                        stream_name_bytes = self.raw_data[offset + name_offset_in_attr : offset + name_offset_in_attr + (name_length * 2)]
                        try:
                            stream_name = stream_name_bytes.decode('utf-16le')
                        except:
                            pass
                            
                    real_size = 0
                    if len(self.raw_data) >= offset + 56:
                        real_size = struct.unpack('<Q', self.raw_data[offset+48:offset+56])[0]
                        
                    runlist_offset = struct.unpack('<H', self.raw_data[offset+32:offset+34])[0]
                    current_run_offset = offset + runlist_offset
                    
                    previous_lcn = 0
                    runs = []
                    while current_run_offset < offset + attr_length:
                        header = self.raw_data[current_run_offset]
                        if header == 0x00: # Fin de los Data Runs
                            break
                            
                        # El byte cabecera se divide en dos nibbles
                        offset_size = header >> 4
                        length_size = header & 0x0F
                        
                        current_run_offset += 1
                        
                        # Leer la longitud (en clústeres)
                        run_length_bytes = self.raw_data[current_run_offset : current_run_offset + length_size]
                        run_length = int.from_bytes(run_length_bytes, byteorder='little', signed=False)
                        current_run_offset += length_size
                        
                        if offset_size > 0:
                            # Leer el offset LCN (puede ser negativo, relativo al anterior)
                            run_offset_bytes = self.raw_data[current_run_offset : current_run_offset + offset_size]
                            lcn_offset = int.from_bytes(run_offset_bytes, byteorder='little', signed=True)
                            current_run_offset += offset_size
                            
                            # Calcular LCN absoluto
                            absolute_lcn = previous_lcn + lcn_offset
                            previous_lcn = absolute_lcn
                        else:
                            absolute_lcn = 0 # Sparse file
                            
                        runs.append({
                            "start_cluster": absolute_lcn,
                            "length": run_length
                        })
                        
                    stream_info = {
                        "name": stream_name,
                        "is_resident": False,
                        "content": b"",
                        "runs": runs,
                        "size": real_size
                    }
                    self.data_streams.append(stream_info)
                    
                    if not stream_name: # Flujo principal
                        self.is_resident_data = False
                        self.data_runs = runs
                        self.data_size = real_size
            
            self.attributes.append({
                "type": hex(attr_type),
                "length": attr_length,
                "resident": not non_resident_flag
            })
            
            offset += attr_length

