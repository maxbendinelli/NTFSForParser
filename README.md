# 🕵️‍♂️ NTFSForParser - Framework Forense Educativo

<div align="center">
  <img src="assets/logo.png" alt="NTFSForParser Logo" width="400"/>
</div>


**NTFSForParser** es un framework interactivo desarrollado en Python, diseñado con un enfoque netamente **educativo y pedagógico**. Su objetivo es permitir a los estudiantes de informática forense sumergirse en las profundidades de los sistemas de archivos, entendiendo las estructuras de bajo nivel (hexadecimal), metadatos, y técnicas de recuperación sin depender de interfaces gráficas complejas o cajas negras.

Actualmente soporta análisis profundo sobre particiones **FAT32** y **NTFS**, e inspección base para **Ext4** (Linux), procesando tanto imágenes crudas (`.dd`, `.raw`, fragmentadas `.001`) como imágenes adquiridas en formato **EnCase (`.e01`)**.

---

## 🚀 Características Principales

1. **Shell Interactivo Forense:** Navega por la imagen de disco utilizando una interfaz de línea de comandos similar a Bash, permitiendo saltar de sector en sector, interpretar clústeres, o moverte por el árbol de directorios de la imagen investigada.
2. **Soporte MACB Total:** Parseo y extracción nativa de metadatos temporales:
   - Fechas MS-DOS para entornos FAT.
   - Fechas FILETIME (`$STANDARD_INFORMATION`) de 100-nanosegundos para MFT (NTFS).
3. **Navegación Jerárquica:** El comando `cd` te permite entrar a carpetas y el comando `ls` te muestra el contenido en vivo.
4. **Data Carving y Recuperación:** Usa el comando `recover` para demostrar la técnica de *File Carving* de archivos borrados contiguos en FAT32 directamente desde la estructura de metadatos.
5. **Comprobación de Integridad:** Usa `hash_check` para leer tu imagen completa y comparar su hash MD5 con el original (si está embebido en E01), asegurando la **Cadena de Custodia**.
6. **Múltiples Formatos Soportados:** Imágenes RAW completas, Divididas/Split (001, 002) y contenedores EnCase (E01).

---

## ⚙️ Requisitos e Instalación

Este framework utiliza componentes nativos de la librería estándar de Python (`struct`, `hashlib`, `cmd`, `argparse`, etc.) para fomentar el aprendizaje y no depender de dependencias mágicas. 

La **única** excepción es la librería para leer el formato propietario E01.

### 1. Requisitos
- Python 3.8+
- Instalar las dependencias listadas en el `requirements.txt`:
  ```bash
  pip install -r requirements.txt
  ```
  *(Nota: Esto instalará `libewf-python`, necesario para manejar compresión e indexación de contenedores `.e01`)*

### 2. Uso y Arranque
Para arrancar el analizador, simplemente ejecuta `main.py` pasándole la ruta de tu imagen forense.
*(Nota: Si intentas abrir un disco físico `\\.\PhysicalDrive0`, asegúrate de correr tu consola como Administrador).*

```bash
# Iniciar el shell interactivo
python main.py ruta_a_la_imagen.e01

# Ejecución rápida por CLI sin entrar a la shell
python main.py imagen.dd --part 0 --cluster 500
python main.py imagen.dd --identify-sector 2048
python main.py imagen.dd --part 0 --runs "Zone.Identifier"
python main.py imagen.dd --part 0 --dump-clusters 100 +50 volcado.bin
```

---

## 💻 Comandos del Shell

Una vez dentro de la consola `Forense >`, tienes a tu disposición un arsenal de comandos. Escribe `help` para ver la lista en cualquier momento.

### Gestión de Particiones e Imágenes
- `partitions`: Lista todas las particiones encontradas en la Tabla de Particiones (MBR).
- `select <num>`: Activa y monta internamente una de las particiones listadas.
- `imageinfo`: Imprime todos los metadatos forenses almacenados por el perito si la imagen es un contenedor EnCase (.e01).
- `hash_check`: Recalcula el Hash MD5 de la imagen completa byte por byte y lo compara contra el original para alertar de corrupción o alteración de evidencia.

### Inspección de Bajo Nivel
- `hexdump <offset>`: Volcado hexadecimal puro desde el inicio del archivo.
- `sector <lba>`: Muestra el contenido físico en el LBA (Logical Block Addressing) indicado.
- `cluster <num>`: Muestra el clúster lógico calculando los offsets relativos a la partición actual.
- `identify sector <num>` (o `cluster`): Lee los Magic Bytes y firmas de la cabecera e intenta adivinar qué estructura es (VBR, Registro MFT, Inicio de PDF, Zip, JPEG, etc).

### Navegación del File System (FAT / NTFS / Ext4)
- `vbr`: Desgrana y traduce los valores del Volume Boot Record o BPB.
- `ls`: Lista los archivos, directorios, sus estados de borrado y fechas de modificación. Soporta lectura de Inodo 2 en Ext4.
- `cd <carpeta>`: Adéntrate en los directorios del File System. Usa `cd ..` para volver atrás.
- `info <id>`: Muestra toda la meta-información técnica de ese archivo (Atributos, Tamaño, Fechas completas, Residentes vs No-Residentes). ¡Avisa si existen flujos ADS ocultos en NTFS!
- `runs <id | nombre>`: Imprime las direcciones físicas del disco donde el archivo guarda su información. Soporta Cadenas FAT, Data Runs (NTFS) y Árbol de Extents (Ext4). Puedes buscar flujos específicos como `runs 12:Zone.Identifier`.

### Lectura y Recuperación de Evidencia
- `cat <nombre | id | sector X | cluster Y>`: Imprime por consola el texto o vuelca el hexdump de un archivo o bloque de disco. Soporta sintaxis `cat id:stream_name` para extraer ADS. Ensambla archivos No-Residentes.
- `extract <id> <ruta_destino>`: Copia de forma forense el archivo (residente o no-residente) desde la imagen de disco hacia tu PC.
- `recover <id> <ruta_destino>`: Realiza un file carving simple para archivos borrados en FAT32, asumiendo contigüidad basándose en el registro original de su tamaño y clúster inicial.
- `dump_clusters <inicio> <fin | +cantidad> <destino>` (o `dump_blocks`): Extrae un rango directo de clústeres o bloques crudos del disco. Ej: `dump_clusters 100 +50 out.bin`.
- `search [-r] <patron>`: Busca un texto o expresión regular (-r) a lo largo de toda la partición. Soporta automáticamente codificación ASCII/UTF-8 y UTF-16LE (común en MFT). Extrae el contexto y su offset físico.
- `find_orphans [limite]`: Escanea la MFT (NTFS) en busca de archivos huérfanos (cuyo directorio padre ha sido borrado o no existe).

### Sistemas Ext4 (Linux)
- `superblock`: Lee las configuraciones maestras de la partición Linux mostrando inodos, bloques y timestamps de montaje.
- `ls / cd / cat / extract`: Soporte integrado nativo en la capa de Extents de Ext4 para listar carpetas (desde el Inodo 2) y extraer archivos crudos a disco.

---

> *Desarrollado para entornos académicos y enseñanza de análisis binario y file systems.*
