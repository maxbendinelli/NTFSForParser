import tkinter as tk
from tkinter import ttk
import struct
import os

class ForensicGui:
    """
    Interfaz Gráfica (GUI) Interactiva en Tkinter para el Framework Forense (Autopsy-Style).
    Muestra la distribución física de particiones, un árbol jerárquico de archivos en caliente
    y el mapa visual de ocupación de clústeres.
    """
    def __init__(self, data_source, mbr_parser, selected_partition=None, on_partition_select=None):
        self.data_source = data_source
        self.mbr_parser = mbr_parser
        self.selected_partition = selected_partition
        self.on_partition_select = on_partition_select
        
        # Mapeo de nodos del árbol jerárquico a sus objetos correspondientes
        # Estructura: node_id -> {"type": "part"|"dir"|"file", "part_idx": idx, "dir_id": id, "file_info": info}
        self.tree_nodes = {}
        self.active_parsers = {} # Cache de parsers cargados en caliente por partición
        
        self.root = tk.Tk()
        self.root.title("Framework Educativo Forense - Cluster Analyzer")
        self.root.geometry("1100x750")
        self.root.configure(bg="#1e1e1e")
        
        # Configurar estilos oscuros y modernos
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", background="#1e1e1e", foreground="#ffffff")
        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Helvetica", 10))
        self.style.configure("TFrame", background="#1e1e1e")
        self.style.configure("Header.TLabel", font=("Helvetica", 14, "bold"))
        self.style.configure("Stat.TLabel", font=("Helvetica", 10, "bold"))
        self.style.configure("TNotebook", background="#1e1e1e", borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#2d2d2d", foreground="#ffffff", font=("Helvetica", 10), padding=(10, 5))
        self.style.map("TNotebook.Tab", background=[("selected", "#1a73e8")], foreground=[("selected", "#ffffff")])
        self.style.configure("Treeview", background="#2d2d2d", foreground="#ffffff", fieldbackground="#2d2d2d", rowheight=22)
        self.style.map("Treeview", background=[("selected", "#1a73e8")], foreground=[("selected", "#ffffff")])
        
        self._create_widgets()
        self._load_disk_layout()
        self._load_data_source_tree()
        
        if self.selected_partition is not None:
            self._load_cluster_map()
            
    def _create_widgets(self):
        # 1. Cabecera superior
        header_frame = ttk.Frame(self.root, padding=10)
        header_frame.pack(fill="x")
        
        image_name = "Imagen de Disco"
        if hasattr(self.data_source, "image_path"):
            image_name = os.path.basename(self.data_source.image_path)
        elif hasattr(self.data_source, "image_paths") and self.data_source.image_paths:
            image_name = os.path.basename(self.data_source.image_paths[0])
            
        ttk.Label(header_frame, text=f"Data Source: {image_name}", style="Header.TLabel").pack(anchor="w")
        
        # 2. Distribución del Disco Físico (Barra de Particiones)
        disk_frame = ttk.LabelFrame(self.root, text=" Distribución Física de Particiones (Clic para seleccionar) ", padding=10)
        disk_frame.pack(fill="x", padx=15, pady=5)
        
        self.disk_canvas = tk.Canvas(disk_frame, height=60, bg="#2d2d2d", highlightthickness=0)
        self.disk_canvas.pack(fill="x", pady=5)
        self.disk_canvas.bind("<Button-1>", self._on_disk_canvas_click)
        
        # 3. Notebook de Pestañas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Pestaña 1: Explorador de Archivos
        self.tab_explorer = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_explorer, text=" Explorador Forense ")
        self._create_explorer_widgets()
        
        # Pestaña 2: Mapa de Clústeres (Defragmenter Style)
        self.tab_clusters = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_clusters, text=" Mapa Visual de Clústeres ")
        self._create_clusters_widgets()
        
    def _create_explorer_widgets(self):
        # PanedWindow horizontal para dividir el árbol del contenido
        paned = ttk.PanedWindow(self.tab_explorer, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Panel Izquierdo: Treeview de directorios
        left_frame = ttk.Frame(paned, width=320)
        paned.add(left_frame, weight=1)
        
        self.tree = ttk.Treeview(left_frame, show="tree", selectmode="browse")
        self.tree.pack(fill="both", expand=True, side="left")
        
        scroll_y = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        scroll_y.pack(fill="y", side="right")
        self.tree.configure(yscrollcommand=scroll_y.set)
        
        self.tree.bind("<<TreeviewOpen>>", self._on_tree_expand)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        
        # Panel Derecho: Metadatos del archivo y Visor de Hexdump
        right_frame = ttk.Frame(paned, width=580)
        paned.add(right_frame, weight=2)
        
        # Panel superior de metadatos
        self.meta_frame = ttk.LabelFrame(right_frame, text=" Información de Archivos y Metadatos ", padding=10)
        self.meta_frame.pack(fill="x", pady=(0, 5))
        
        self.lbl_file_name = ttk.Label(self.meta_frame, text="Ningún archivo seleccionado", font=("Helvetica", 11, "bold"), foreground="#1a73e8")
        self.lbl_file_name.pack(anchor="w", pady=3)
        
        self.lbl_file_meta = ttk.Label(self.meta_frame, text="", justify="left")
        self.lbl_file_meta.pack(anchor="w", pady=3)
        
        # Panel inferior de Hexdump
        self.hex_frame = ttk.LabelFrame(right_frame, text=" Visores Forenses de Previsualización ", padding=10)
        self.hex_frame.pack(fill="both", expand=True)
        
        self.preview_notebook = ttk.Notebook(self.hex_frame)
        self.preview_notebook.pack(fill="both", expand=True)
        
        # Pestaña A: Contenido / Datos
        tab_content = ttk.Frame(self.preview_notebook)
        self.preview_notebook.add(tab_content, text=" Contenido (Datos) ")
        
        self.txt_hexdump = tk.Text(tab_content, font=("Courier New", 9), bg="#1e1e1e", fg="#55ff55", insertbackground="white", highlightthickness=0)
        self.txt_hexdump.pack(fill="both", expand=True, side="left")
        scroll_hex = ttk.Scrollbar(tab_content, orient="vertical", command=self.txt_hexdump.yview)
        scroll_hex.pack(fill="y", side="right")
        self.txt_hexdump.configure(yscrollcommand=scroll_hex.set)
        
        # Pestaña B: Registro de Sistema de Archivos (Crudo / Estructura)
        tab_structure = ttk.Frame(self.preview_notebook)
        self.preview_notebook.add(tab_structure, text=" Registro de Sistema (Metadatos Crudos) ")
        
        self.txt_raw_metadata = tk.Text(tab_structure, font=("Courier New", 9), bg="#1e1e1e", fg="#55ffff", insertbackground="white", highlightthickness=0)
        self.txt_raw_metadata.pack(fill="both", expand=True, side="left")
        scroll_raw = ttk.Scrollbar(tab_structure, orient="vertical", command=self.txt_raw_metadata.yview)
        scroll_raw.pack(fill="y", side="right")
        self.txt_raw_metadata.configure(yscrollcommand=scroll_raw.set)
        
        # Pestaña C: Vista de Texto (ASCII/ANSI continuo)
        tab_text_view = ttk.Frame(self.preview_notebook)
        self.preview_notebook.add(tab_text_view, text=" Vista de Texto ")
        
        self.txt_text_view = tk.Text(tab_text_view, font=("Courier New", 9), bg="#1e1e1e", fg="#ffffff", insertbackground="white", highlightthickness=0, wrap="char")
        self.txt_text_view.pack(fill="both", expand=True, side="left")
        scroll_text_view = ttk.Scrollbar(tab_text_view, orient="vertical", command=self.txt_text_view.yview)
        scroll_text_view.pack(fill="y", side="right")
        self.txt_text_view.configure(yscrollcommand=scroll_text_view.set)
        
        # Barra de estado inferior estilo Autopsy
        self.lbl_hex_status = ttk.Label(self.hex_frame, text="Cursor pos = 0; clus = N/A; log sec = N/A; phy sec = N/A", font=("Courier New", 9, "bold"), relief="sunken", anchor="w", padding=3)
        self.lbl_hex_status.pack(fill="x", side="bottom", pady=(5, 0))
        
        # Eventos para actualizar la posición en tiempo real
        self.txt_hexdump.bind("<KeyRelease>", self._update_hex_cursor_status)
        self.txt_hexdump.bind("<ButtonRelease-1>", self._update_hex_cursor_status)
        self.txt_raw_metadata.bind("<KeyRelease>", self._update_hex_cursor_status)
        self.txt_raw_metadata.bind("<ButtonRelease-1>", self._update_hex_cursor_status)
        self.txt_text_view.bind("<KeyRelease>", self._update_hex_cursor_status)
        self.txt_text_view.bind("<ButtonRelease-1>", self._update_hex_cursor_status)
        
    def _create_clusters_widgets(self):
        # Panel izquierdo para Canvas de Clústeres
        map_frame = ttk.LabelFrame(self.tab_clusters, text=" Cuadrícula de Clústeres del Volumen ", padding=10)
        map_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        self.cluster_canvas = tk.Canvas(map_frame, bg="#2d2d2d", highlightthickness=0)
        self.cluster_canvas.pack(fill="both", expand=True)
        
        # Panel derecho para estadísticas y leyenda
        stats_frame = ttk.LabelFrame(self.tab_clusters, text=" Detalles y Leyenda del Volumen ", padding=10, width=300)
        stats_frame.pack(side="right", fill="y", padx=5, pady=5)
        stats_frame.pack_propagate(False)
        
        self.lbl_part_name = ttk.Label(stats_frame, text="Selecciona una partición...", style="Stat.TLabel")
        self.lbl_part_name.pack(anchor="w", pady=5)
        
        self.lbl_fs = ttk.Label(stats_frame, text="Sistema de archivos: N/A")
        self.lbl_fs.pack(anchor="w", pady=3)
        
        self.lbl_start_lba = ttk.Label(stats_frame, text="LBA inicio: N/A")
        self.lbl_start_lba.pack(anchor="w", pady=3)
        
        self.lbl_size = ttk.Label(stats_frame, text="Tamaño total: N/A")
        self.lbl_size.pack(anchor="w", pady=3)
        
        self.lbl_clusters = ttk.Label(stats_frame, text="Clústeres totales: N/A")
        self.lbl_clusters.pack(anchor="w", pady=3)
        
        self.lbl_used_clusters = ttk.Label(stats_frame, text="Clústeres usados: N/A")
        self.lbl_used_clusters.pack(anchor="w", pady=3)
        
        self.lbl_free_clusters = ttk.Label(stats_frame, text="Clústeres libres: N/A")
        self.lbl_free_clusters.pack(anchor="w", pady=3)
        
        self.lbl_warning = ttk.Label(stats_frame, text="", wraplength=270, foreground="#ffaa00", font=("Helvetica", 9, "italic"))
        self.lbl_warning.pack(anchor="w", pady=10)
        
        # Leyenda de colores del mapa de clústeres
        legend_frame = ttk.Frame(stats_frame, padding=5)
        legend_frame.pack(fill="x", side="bottom")
        
        self._add_legend_item(legend_frame, "#ff5555", "Metadatos del Sistema (MFT/FAT)")
        self._add_legend_item(legend_frame, "#55ff55", "Totalmente Ocupado (100%)")
        self._add_legend_item(legend_frame, "#55ffff", "Mayormente Ocupado (>50%)")
        self._add_legend_item(legend_frame, "#5555ff", "Parcialmente Ocupado (10%-50%)")
        self._add_legend_item(legend_frame, "#888888", "Ocupación Mínima (<10%)")
        self._add_legend_item(legend_frame, "#3a3a3a", "Totalmente Libre (Unallocated)")
        
    def _add_legend_item(self, parent, color, text):
        item_frame = ttk.Frame(parent)
        item_frame.pack(fill="x", pady=2)
        color_box = tk.Frame(item_frame, width=12, height=12, bg=color)
        color_box.pack(side="left", padx=(0, 5))
        ttk.Label(item_frame, text=text, font=("Helvetica", 8)).pack(side="left")

    def _load_disk_layout(self):
        self.disk_canvas.delete("all")
        if not self.mbr_parser:
            return
            
        try:
            total_size_bytes = self.data_source.get_size()
            total_sectors = total_size_bytes // 512
        except Exception:
            total_sectors = 100000
            
        self.root.update_idletasks()
        canvas_width = self.disk_canvas.winfo_width()
        if canvas_width <= 1:
            canvas_width = 850
            
        # Determinar bloques
        active_parts = sorted(self.mbr_parser.partitions, key=lambda p: p.start_lba)
        blocks = []
        current_lba = 34 if self.mbr_parser.is_gpt else 1
        
        for idx, part in enumerate(active_parts):
            original_idx = self.mbr_parser.partitions.index(part)
            if part.start_lba > current_lba:
                blocks.append({
                    "start": current_lba,
                    "end": part.start_lba - 1,
                    "type": "unallocated",
                    "part_idx": None
                })
            blocks.append({
                "start": part.start_lba,
                "end": part.start_lba + part.size_in_sectors - 1,
                "type": "partition",
                "part_idx": original_idx,
                "name": part.type_name
            })
            current_lba = max(current_lba, part.start_lba + part.size_in_sectors)
            
        end_data_lba = total_sectors - 33 if self.mbr_parser.is_gpt else total_sectors
        if current_lba < end_data_lba:
            blocks.append({
                "start": current_lba,
                "end": end_data_lba,
                "type": "unallocated",
                "part_idx": None
            })
            
        self.disk_blocks_render_info = []
        colors = ["#2a82e6", "#e67e22", "#27ae60", "#9b59b6", "#16a085", "#f1c40f"]
        
        sum_sectors = sum((b["end"] - b["start"] + 1) for b in blocks)
        num_blocks = len(blocks)
        
        min_width = 45
        reserved_width = num_blocks * min_width
        
        if reserved_width > canvas_width:
            min_width = canvas_width // num_blocks
            reserved_width = num_blocks * min_width
            
        remaining_width = canvas_width - reserved_width
        
        current_x = 0
        for block in blocks:
            size = block["end"] - block["start"] + 1
            if sum_sectors > 0:
                block_w = min_width + (size / sum_sectors) * remaining_width
            else:
                block_w = canvas_width / num_blocks
                
            x1 = current_x
            x2 = current_x + block_w
            x2 = min(canvas_width, x2)
            
            if block == blocks[-1]:
                x2 = canvas_width
                
            current_x = x2
            
            if block["type"] == "unallocated":
                color = "#444444"
                label = f"Libre ({block['end'] - block['start'] + 1} sect.)"
            else:
                color_idx = block["part_idx"] % len(colors)
                color = colors[color_idx]
                label = f"[{block['part_idx']}] {block['name']}"
                
            border_color = "#ffcc00" if block["part_idx"] == self.selected_partition and block["part_idx"] is not None else "#ffffff"
            width_border = 3 if block["part_idx"] == self.selected_partition and block["part_idx"] is not None else 1
            
            rect_id = self.disk_canvas.create_rectangle(x1, 5, x2, 55, fill=color, outline=border_color, width=width_border)
            
            if x2 - x1 > 60:
                self.disk_canvas.create_text((x1 + x2)/2, 30, text=label, fill="#ffffff", font=("Helvetica", 8, "bold"))
                
            self.disk_blocks_render_info.append({
                "rect_id": rect_id,
                "x1": x1,
                "x2": x2,
                "block": block
            })
            
    def _on_disk_canvas_click(self, event):
        for info in self.disk_blocks_render_info:
            if info["x1"] <= event.x <= info["x2"]:
                block = info["block"]
                if block["part_idx"] is not None:
                    self.selected_partition = block["part_idx"]
                    if self.on_partition_select:
                        self.on_partition_select(block["part_idx"])
                    self._load_cluster_map()
                    self._load_disk_layout()
                    
                    # Sincronizar selección en la pestaña de árbol si existe
                    for node_id, node_info in self.tree_nodes.items():
                        if node_info["type"] == "part" and node_info["part_idx"] == block["part_idx"]:
                            self.tree.selection_set(node_id)
                            self.tree.see(node_id)
                            break
                break

    def _load_data_source_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.tree_nodes.clear()
        
        if not self.mbr_parser:
            return
            
        # Nombre de la fuente de datos principal
        ds_name = "Imagen de Disco"
        if hasattr(self.data_source, "image_path"):
            ds_name = os.path.basename(self.data_source.image_path)
            
        root_node = self.tree.insert("", "end", text=ds_name, open=True)
        self.tree_nodes[root_node] = {"type": "root"}
        
        active_parts = sorted(self.mbr_parser.partitions, key=lambda p: p.start_lba)
        current_lba = 34 if self.mbr_parser.is_gpt else 1
        
        # Mapeo de bloques para recrear el árbol jerárquico como Autopsy
        vol_idx = 1
        for idx, part in enumerate(active_parts):
            original_idx = self.mbr_parser.partitions.index(part)
            if part.start_lba > current_lba:
                unalloc_name = f"vol{vol_idx} (Unallocated: {current_lba}-{part.start_lba - 1})"
                unalloc_node = self.tree.insert(root_node, "end", text=unalloc_name)
                self.tree_nodes[unalloc_node] = {"type": "unallocated", "start": current_lba, "end": part.start_lba - 1}
                vol_idx += 1
                
            vol_name = f"vol{vol_idx} ({part.type_name}: {part.start_lba}-{part.start_lba + part.size_in_sectors - 1})"
            part_node = self.tree.insert(root_node, "end", text=vol_name)
            self.tree_nodes[part_node] = {
                "type": "part",
                "part_idx": original_idx,
                "start": part.start_lba,
                "end": part.start_lba + part.size_in_sectors - 1
            }
            vol_idx += 1
            current_lba = max(current_lba, part.start_lba + part.size_in_sectors)
            
            # Instanciar el parser del volumen para ver si tiene estructura lógica
            parser, fs_type, root_id = self._get_volume_parser(original_idx)
            if parser and fs_type != "DESCONOCIDO":
                # Agregar dummy child para habilitar flecha de expansión
                self.tree.insert(part_node, "end", text="cargando...")
                
        # Espacio libre final
        total_sectors = 100000
        try:
            total_sectors = self.data_source.get_size() // 512
        except:
            pass
        end_data_lba = total_sectors - 33 if self.mbr_parser.is_gpt else total_sectors
        if current_lba < end_data_lba:
            unalloc_name = f"vol{vol_idx} (Unallocated: {current_lba}-{end_data_lba})"
            unalloc_node = self.tree.insert(root_node, "end", text=unalloc_name)
            self.tree_nodes[unalloc_node] = {"type": "unallocated", "start": current_lba, "end": end_data_lba}

    def _get_volume_parser(self, part_idx):
        if part_idx in self.active_parsers:
            return self.active_parsers[part_idx]
            
        part = self.mbr_parser.partitions[part_idx]
        vbr_data = self.data_source.read(part.start_offset, 512)
        sb_data = self.data_source.read(part.start_offset + 1024, 64)
        
        from fs.fat_parser import FATParser
        from fs.exfat_parser import exFATParser
        from fs.ntfs_parser import NTFSParser
        from fs.ext4_parser import Ext4Parser
        
        parser, fs_type, root_id = None, "DESCONOCIDO", None
        
        if len(vbr_data) >= 11 and vbr_data[3:11] == b'-FVE-FS-':
            fs_type = "BitLocker (Cifrado)"
        elif len(vbr_data) >= 11 and vbr_data[3:11] == b'EXFAT   ':
            try:
                parser = exFATParser(self.data_source, part)
                fs_type = "exFAT"
                root_id = parser.boot_sector.root_directory_cluster
            except:
                pass
        elif len(vbr_data) >= 11 and vbr_data[3:11] == b'NTFS    ':
            try:
                parser = NTFSParser(self.data_source, part)
                fs_type = "NTFS"
                root_id = 5
            except:
                pass
        elif len(sb_data) >= 58 and sb_data[56:58] == b'\x53\xef':
            try:
                parser = Ext4Parser(self.data_source, part)
                fs_type = "Ext4"
                root_id = 2
            except:
                pass
        elif len(vbr_data) >= 512 and vbr_data[510:512] == b'\x55\xaa':
            try:
                bytes_sec = struct.unpack('<H', vbr_data[11:13])[0]
                sec_clust = vbr_data[13]
                if bytes_sec in (512, 1024, 2048, 4096) and sec_clust in (1, 2, 4, 8, 16, 32, 64, 128):
                    parser = FATParser(self.data_source, part)
                    fs_type = f"FAT{parser.boot_sector.fat_type}"
                    root_id = parser.boot_sector.root_cluster if parser.boot_sector.fat_type == 32 else 0
                    if parser.boot_sector.fat_type == 32 and root_id == 0:
                        root_id = 2
            except Exception:
                pass
                
        self.active_parsers[part_idx] = (parser, fs_type, root_id)
        return parser, fs_type, root_id

    def _on_tree_expand(self, event):
        node_id = self.tree.focus()
        if not node_id:
            return
            
        node_info = self.tree_nodes.get(node_id)
        if not node_info:
            return
            
        # Si ya se cargaron los hijos reales, no hacer nada
        children = self.tree.get_children(node_id)
        if len(children) == 1 and self.tree.item(children[0], "text") == "cargando...":
            self.tree.delete(children[0]) # Borrar dummy
            
            # Cargar dinámicamente según sea partición o directorio
            if node_info["type"] == "part":
                part_idx = node_info["part_idx"]
                parser, fs_type, root_id = self._get_volume_parser(part_idx)
                if parser:
                    self._populate_directory(node_id, part_idx, parser, fs_type, root_id)
            elif node_info["type"] == "dir":
                part_idx = node_info["part_idx"]
                parser, fs_type, _ = self._get_volume_parser(part_idx)
                dir_id = node_info["dir_id"]
                if parser:
                    self._populate_directory(node_id, part_idx, parser, fs_type, dir_id)

    def _populate_directory(self, parent_node, part_idx, parser, fs_type, dir_id):
        entries = []
        
        if "NTFS" in fs_type:
            # Escanear primeros 200 registros de la MFT
            for i in range(200):
                if i == 5 and dir_id == 5:
                    continue
                try:
                    record = parser.get_mft_record(i)
                    if record.signature != 'FILE':
                        continue
                    record.parse_attributes()
                    if record.parent_mft_id == dir_id and record.file_name:
                        entries.append({
                            "id": i,
                            "name": record.file_name,
                            "is_dir": record.is_directory(),
                            "is_deleted": not record.is_in_use(),
                            "size": record.data_size if hasattr(record, "data_size") else 0,
                            "created": record.created if record.created else "N/A",
                            "modified": record.modified if record.modified else "N/A",
                            "accessed": record.accessed if record.accessed else "N/A",
                            "data_runs": getattr(record, "data_runs", []),
                            "is_resident": getattr(record, "is_resident_data", True),
                            "content": getattr(record, "data_content", b"")
                        })
                except Exception:
                    pass
                    
        elif "FAT" in fs_type:
            try:
                # Leer desde FATParser o exFATParser
                if fs_type == "exFAT":
                    raw_entries = parser.get_directory_entries(dir_id)
                else:
                    raw_entries = parser.get_directory_entries(dir_id)
                    
                for entry in raw_entries:
                    if entry.name in (".", ".."):
                        continue
                    entries.append({
                        "id": entry.start_cluster,
                        "name": entry.name,
                        "is_dir": entry.is_directory,
                        "is_deleted": entry.is_deleted,
                        "size": entry.size,
                        "created": entry.created if entry.created else "N/A",
                        "modified": entry.modified if entry.modified else "N/A",
                        "accessed": entry.accessed if entry.accessed else "N/A",
                        "entry_obj": entry,
                        "raw_bytes": getattr(entry, "raw_bytes", b"")
                    })
            except Exception:
                pass
                
        elif "Ext4" in fs_type:
            try:
                raw_entries = parser.get_directory_entries(dir_id)
                for entry in raw_entries:
                    if entry["name"] in (".", ".."):
                        continue
                    entries.append({
                        "id": entry["inode"],
                        "name": entry["name"],
                        "is_dir": entry["type_str"] == "DIR",
                        "is_deleted": False,
                        "size": entry.get("size", 0),
                        "created": entry.get("created", "N/A"),
                        "modified": entry.get("modified", "N/A"),
                        "accessed": entry.get("accessed", "N/A")
                    })
            except Exception:
                pass

        # Insertar entradas ordenadas (directorios primero)
        entries_sorted = sorted(entries, key=lambda e: (not e["is_dir"], e["name"].lower()))
        
        for e in entries_sorted:
            prefix = "📁 " if e["is_dir"] else "📄 "
            if e["is_deleted"]:
                prefix = "🗑️ [Borrado] "
                
            node_text = f"{prefix}{e['name']}"
            item_node = self.tree.insert(parent_node, "end", text=node_text)
            
            if e["is_deleted"]:
                self.tree.item(item_node, tags=("deleted",))
                self.tree.tag_configure("deleted", foreground="#ff5555")
                
            if e["is_dir"]:
                self.tree_nodes[item_node] = {
                    "type": "dir",
                    "part_idx": part_idx,
                    "dir_id": e["id"],
                    "meta": e
                }
                # Insertar dummy child para permitir su expansión futura
                self.tree.insert(item_node, "end", text="cargando...")
            else:
                self.tree_nodes[item_node] = {
                    "type": "file",
                    "part_idx": part_idx,
                    "meta": e
                }

    def _on_tree_select(self, event):
        node_id = self.tree.focus()
        if not node_id:
            return
            
        node_info = self.tree_nodes.get(node_id)
        if not node_info:
            return
            
        self.txt_hexdump.delete("1.0", tk.END)
        self.txt_raw_metadata.delete("1.0", tk.END)
        self.txt_text_view.delete("1.0", tk.END)
        self.lbl_file_name.config(text="Ningún archivo seleccionado")
        self.lbl_file_meta.config(text="")
        
        if node_info["type"] == "file":
            meta = node_info["meta"]
            self.lbl_file_name.config(text=meta["name"])
            
            status_str = "BORRADO (Recuperable)" if meta["is_deleted"] else "Activo"
            metadata_text = (
                f"Estado: {status_str}\n"
                f"Tamaño: {meta['size']} bytes\n"
                f"ID Lógico / Inodo: {meta['id']}\n"
                f"Creación: {meta['created']}\n"
                f"Modificación: {meta['modified']}\n"
                f"Último Acceso: {meta['accessed']}"
            )
            self.lbl_file_meta.config(text=metadata_text)
            
            # Cargar vista previa del archivo y metadatos crudos
            parser, fs_type, _ = self._get_volume_parser(node_info["part_idx"])
            file_bytes = b""
            
            if "NTFS" in fs_type:
                try:
                    if meta.get("is_resident", True):
                        file_bytes = meta.get("content", b"")
                    else:
                        file_bytes = parser.read_data_runs(meta.get("data_runs", []), min(meta["size"], 4096))
                        
                    # Cargar registro MFT crudo
                    record = parser.get_mft_record(meta["id"])
                    v_dump = self._hexdump_formatter(record.raw_data)
                    header = (
                        f"================================================================================\n"
                        f"        REGISTRO MFT {meta['id']} EN CRUDO (NTFS) - {len(record.raw_data)} BYTES\n"
                        f"================================================================================\n\n"
                    )
                    self.txt_raw_metadata.insert("1.0", header + v_dump)
                except:
                    pass
            elif "FAT" in fs_type:
                try:
                    # Recuperar cadena de clústeres y leer
                    start_clust = meta["id"]
                    if start_clust > 0:
                        chain = parser.get_fat_chain(start_clust)
                        buffer = bytearray()
                        for c in chain[:8]: # Leer primeros 8 clústeres máximo
                            offset = parser.get_cluster_offset(c)
                            buffer.extend(self.data_source.read(offset, parser.get_cluster_size()))
                        file_bytes = bytes(buffer[:meta["size"]])
                        
                    # Cargar Directory Entry cruda
                    raw_b = meta.get("raw_bytes", b"")
                    if raw_b:
                        v_dump = self._hexdump_formatter(raw_b)
                        header = (
                            f"================================================================================\n"
                            f"        DIRECTORY ENTRY EN CRUDO ({fs_type}) - {len(raw_b)} BYTES\n"
                            f"================================================================================\n\n"
                        )
                        self.txt_raw_metadata.insert("1.0", header + v_dump)
                except:
                    pass
            elif "Ext4" in fs_type:
                try:
                    file_bytes = parser.read_file(meta["id"])[:4096]
                    
                    # Cargar Inodo crudo
                    inode_bytes = parser.get_inode(meta["id"])
                    v_dump = self._hexdump_formatter(inode_bytes)
                    header = (
                        f"================================================================================\n"
                        f"        ESTRUCTURA DE INODO {meta['id']} EN CRUDO (Ext4) - {len(inode_bytes)} BYTES\n"
                        f"================================================================================\n\n"
                    )
                    self.txt_raw_metadata.insert("1.0", header + v_dump)
                except:
                    pass
                    
            if file_bytes:
                # Mostrar Hexdump y Vista de Texto
                dump_str = self._hexdump_formatter(file_bytes[:512])
                self.txt_hexdump.insert("1.0", dump_str)
                text_str = self._text_formatter(file_bytes[:4096])
                self.txt_text_view.insert("1.0", text_str)
            else:
                self.txt_hexdump.insert("1.0", "[Sin datos o archivo residente vacío / cifrado]")
                self.txt_text_view.insert("1.0", "[Sin datos]")
                
        elif node_info["type"] == "dir":
            meta = node_info["meta"]
            self.lbl_file_name.config(text=f"Directorio: {meta['name']}")
            self.lbl_file_meta.config(text=f"ID Lógico: {meta['id']}\nCreación: {meta['created']}\nModificación: {meta['modified']}")
            
            parser, fs_type, _ = self._get_volume_parser(node_info["part_idx"])
            dir_bytes = b""
            
            if "NTFS" in fs_type:
                try:
                    record = parser.get_mft_record(meta["id"])
                    v_dump = self._hexdump_formatter(record.raw_data)
                    header = (
                        f"================================================================================\n"
                        f"        REGISTRO MFT {meta['id']} EN CRUDO (NTFS) - {len(record.raw_data)} BYTES\n"
                        f"================================================================================\n\n"
                    )
                    self.txt_raw_metadata.insert("1.0", header + v_dump)
                    dir_bytes = record.raw_data
                except:
                    pass
            elif "FAT" in fs_type:
                try:
                    raw_b = meta.get("raw_bytes", b"")
                    if raw_b:
                        v_dump = self._hexdump_formatter(raw_b)
                        header = (
                            f"================================================================================\n"
                            f"        DIRECTORY ENTRY EN CRUDO ({fs_type}) - {len(raw_b)} BYTES\n"
                            f"================================================================================\n\n"
                        )
                        self.txt_raw_metadata.insert("1.0", header + v_dump)
                        
                    start_clust = meta["id"]
                    if start_clust > 0:
                        chain = parser.get_fat_chain(start_clust)
                        buffer = bytearray()
                        for c in chain[:8]: # Leer hasta 8 clústeres
                            offset = parser.get_cluster_offset(c)
                            buffer.extend(self.data_source.read(offset, parser.get_cluster_size()))
                        dir_bytes = bytes(buffer)
                    elif start_clust == 0 and hasattr(parser, "get_root_dir_offset"):
                        root_offset = parser.get_root_dir_offset()
                        root_size = parser.boot_sector.root_entry_count * 32
                        dir_bytes = self.data_source.read(root_offset, root_size)
                except:
                    pass
            elif "Ext4" in fs_type:
                try:
                    inode_bytes = parser.get_inode(meta["id"])
                    v_dump = self._hexdump_formatter(inode_bytes)
                    header = (
                        f"================================================================================\n"
                        f"        ESTRUCTURA DE INODO {meta['id']} EN CRUDO (Ext4) - {len(inode_bytes)} BYTES\n"
                        f"================================================================================\n\n"
                    )
                    self.txt_raw_metadata.insert("1.0", header + v_dump)
                    
                    dir_bytes = parser.read_file(meta["id"])[:4096]
                except:
                    pass
                    
            if dir_bytes:
                dump_str = self._hexdump_formatter(dir_bytes[:4096])
                self.txt_hexdump.insert("1.0", dump_str)
                text_str = self._text_formatter(dir_bytes[:4096])
                self.txt_text_view.insert("1.0", text_str)
            else:
                self.txt_hexdump.insert("1.0", "[Sin datos o directorio vacío]")
                self.txt_text_view.insert("1.0", "[Sin datos]")
            
        elif node_info["type"] == "part":
            self.selected_partition = node_info["part_idx"]
            if self.on_partition_select:
                self.on_partition_select(node_info["part_idx"])
            self._load_cluster_map()
            self._load_disk_layout()
            
            part = self.mbr_parser.partitions[self.selected_partition]
            parser, fs_type, _ = self._get_volume_parser(self.selected_partition)
            
            self.lbl_file_name.config(text=f"Partición [{self.selected_partition}]: {part.type_name}")
            
            meta_text = (
                f"LBA de inicio : {part.start_lba}\n"
                f"LBA de fin    : {part.start_lba + part.size_in_sectors - 1}\n"
                f"Tamaño total  : {part.size_in_bytes / (1024**3):.2f} GB ({part.size_in_bytes} bytes)\n"
                f"Filesystem    : {fs_type}"
            )
            self.lbl_file_meta.config(text=meta_text)
            
            if fs_type == "BitLocker (Cifrado)":
                explanation = (
                    "================================================================================\n"
                    "        EXPLICACIÓN FORENSE DE VOLUMEN CIFRADO (BitLocker Full Volume Encryption)\n"
                    "================================================================================\n\n"
                    "Este volumen está cifrado y protegido mediante cifrado de disco completo de Windows.\n\n"
                    "¿Por qué no podemos listar sus directorios ni archivos en este framework didáctico?\n"
                    "1. La Master File Table (MFT) de NTFS y todos los bloques de datos lógicos del volumen\n"
                    "   están encriptados mediante algoritmos simétricos robustos (como AES-CBC o AES-XTS).\n"
                    "2. Para descifrar las estructuras del filesystem se requiere el uso de la clave de\n"
                    "   recuperación de 48 dígitos (Recovery Password) o un archivo de clave de inicio (.bek)\n"
                    "   para descifrar la clave maestra del volumen (VMK) y luego la clave del volumen (FVEK).\n"
                    "3. Las herramientas forenses logran descifrar este tipo de volúmenes cuando el analista proporciona dicha\n"
                    "   clave o si detecta que el volumen se encuentra temporalmente 'suspendido' (Clear Key),\n"
                    "   permitiéndole reconstruir el sistema de archivos NTFS en caliente en memoria virtual.\n\n"
                    "Acciones forenses posibles sin descifrado en este framework:\n"
                    "- Ejecutar File Carving ('carve') sobre la partición buscando firmas físicas directamente.\n"
                    "- Realizar análisis crudo de sectores usando 'hexdump' o 'sector'."
                )
                self.txt_hexdump.insert("1.0", explanation)
                self.txt_text_view.insert("1.0", "[Cifrado]")
            else:
                try:
                    vbr_bytes = self.data_source.read(part.start_offset, 512)
                    vbr_dump = self._hexdump_formatter(vbr_bytes)
                    header = (
                        f"================================================================================\n"
                        f"        VOLCADO HEXADECIMAL DEL SECTOR DE ARRANQUE (VBR) - {fs_type}\n"
                        f"================================================================================\n\n"
                    )
                    self.txt_hexdump.insert("1.0", header + vbr_dump)
                    vbr_text = self._text_formatter(vbr_bytes)
                    self.txt_text_view.insert("1.0", vbr_text)
                except Exception as e:
                    self.txt_hexdump.insert("1.0", f"[Error al leer sector de arranque: {e}]")
                    self.txt_text_view.insert("1.0", f"[Error: {e}]")
            
        self._update_hex_cursor_status()

    def _hexdump_formatter(self, data):
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if (32 <= b < 127) or (160 <= b < 256) else "." for b in chunk)
            lines.append(f"{i:04x} | {hex_part:<47} | {ascii_part}")
        return "\n".join(lines)

    def _load_cluster_map(self):
        self.cluster_canvas.delete("all")
        if self.selected_partition is None or not self.mbr_parser:
            return
            
        part = self.mbr_parser.partitions[self.selected_partition]
        self.lbl_part_name.config(text=f"Partición [{self.selected_partition}]: {part.type_name}")
        
        parser, fs_type, root_id = self._get_volume_parser(self.selected_partition)
        
        total_clusters = 1000
        bytes_per_cluster = 4096
        mft_start = -1
        fat_start = -1
        
        if parser:
            if "NTFS" in fs_type:
                bytes_per_cluster = parser.vbr.bytes_per_cluster
                total_clusters = part.size_in_bytes // bytes_per_cluster
                mft_start = parser.vbr.mft_start_cluster
            elif "FAT" in fs_type or "exFAT" in fs_type:
                if hasattr(parser, "get_cluster_size"):
                    bytes_per_cluster = parser.get_cluster_size()
                elif hasattr(parser, "bytes_per_cluster"):
                    bytes_per_cluster = parser.bytes_per_cluster
                elif hasattr(parser, "boot_sector") and hasattr(parser.boot_sector, "sectors_per_cluster") and hasattr(parser.boot_sector, "bytes_per_sector"):
                    bytes_per_cluster = parser.boot_sector.sectors_per_cluster * parser.boot_sector.bytes_per_sector
                else:
                    bytes_per_cluster = 4096
                total_clusters = part.size_in_bytes // bytes_per_cluster
                if hasattr(parser, "vbr"):
                    vbr = parser.vbr
                    if hasattr(vbr, "reserved_sectors"):
                        fat_start = vbr.reserved_sectors
            elif "Ext" in fs_type:
                if hasattr(parser, "superblock") and hasattr(parser.superblock, "block_size"):
                    bytes_per_cluster = parser.superblock.block_size
                else:
                    bytes_per_cluster = 4096
                total_clusters = part.size_in_bytes // bytes_per_cluster
                        
        total_clusters = max(1, total_clusters)
        self.lbl_fs.config(text=f"Sistema de archivos: {fs_type}")
        self.lbl_start_lba.config(text=f"LBA inicio: {part.start_lba}")
        self.lbl_size.config(text=f"Tamaño total: {part.size_in_bytes / (1024**2):.2f} MB")
        self.lbl_clusters.config(text=f"Clústeres totales: {total_clusters}")
        
        bitmap = [False] * total_clusters
        has_real_data = False
        
        if fs_type == "NTFS" and parser:
            try:
                mft_6 = parser.get_mft_record(6)
                mft_6.parse_attributes()
                bitmap_bytes = b""
                if mft_6.is_resident_data:
                    bitmap_bytes = mft_6.data_content
                else:
                    bitmap_bytes = parser.read_data_runs(mft_6.data_runs, mft_6.data_size)
                    
                if bitmap_bytes:
                    for i in range(min(total_clusters, len(bitmap_bytes) * 8)):
                        byte_idx = i // 8
                        bit_idx = i % 8
                        if byte_idx < len(bitmap_bytes):
                            bitmap[i] = bool(bitmap_bytes[byte_idx] & (1 << bit_idx))
                    has_real_data = True
            except:
                pass
        elif "FAT" in fs_type and parser:
            try:
                # Leer primeros clusters de la FAT
                fat_abs_offset = part.start_offset + (fat_start * 512) if fat_start != -1 else part.start_offset + 512
                entry_size = 4 if "32" in fs_type else 2
                max_read = min(total_clusters, 2000)
                fat_raw = self.data_source.read(fat_abs_offset, max_read * entry_size)
                for i in range(min(total_clusters, len(fat_raw) // entry_size)):
                    if entry_size == 4:
                        val = struct.unpack('<I', fat_raw[i*4 : (i+1)*4])[0] & 0x0FFFFFFF
                        bitmap[i] = (val != 0x00000000)
                    else:
                        val = struct.unpack('<H', fat_raw[i*2 : (i+1)*2])[0]
                        bitmap[i] = (val != 0x0000)
                has_real_data = True
            except:
                pass
                
        if not has_real_data:
            import random
            random.seed(self.selected_partition)
            for i in range(total_clusters):
                if i < 80:
                    bitmap[i] = True
                else:
                    bitmap[i] = (random.randint(0, 100) < 30)
                    
        if fs_type == "BitLocker (Cifrado)":
            self.lbl_warning.config(text="⚠️ Advertencia: Partición cifrada con BitLocker. Los datos lógicos están protegidos y no es posible parsear clústeres. Mostrando simulación didáctica.")
        elif fs_type == "DESCONOCIDO":
            self.lbl_warning.config(text="⚠️ Advertencia: Partición sin sistema de archivos compatible. Mostrando simulación didáctica de ocupación.")
        elif not has_real_data:
            self.lbl_warning.config(text="⚠️ Nota: No se pudo leer el bitmap de ocupación. Mostrando simulación didáctica.")
        else:
            self.lbl_warning.config(text="")
            
        used_count = sum(1 for b in bitmap if b)
        self.lbl_used_clusters.config(text=f"Clústeres usados: {used_count} ({used_count/total_clusters*100:.1f}%)")
        self.lbl_free_clusters.config(text=f"Clústeres libres: {total_clusters - used_count}")
        
        self.root.update_idletasks()
        cw = self.cluster_canvas.winfo_width()
        ch = self.cluster_canvas.winfo_height()
        if cw <= 1:
            cw, ch = 550, 420
            
        cols = 40
        rows = 20
        grid_size = cols * rows
        clusters_per_block = max(1, total_clusters // grid_size)
        
        block_w = cw / cols
        block_h = ch / rows
        
        for r in range(rows):
            for c in range(cols):
                block_idx = r * cols + c
                start_c = block_idx * clusters_per_block
                end_c = min(total_clusters, start_c + clusters_per_block)
                
                range_bitmap = bitmap[start_c:end_c]
                if not range_bitmap:
                    continue
                    
                ratio = sum(1 for b in range_bitmap if b) / len(range_bitmap)
                
                is_system = False
                if "NTFS" in fs_type and mft_start != -1:
                    if start_c <= mft_start < end_c or (start_c <= mft_start + 32 < end_c):
                        is_system = True
                elif "FAT" in fs_type and fat_start != -1:
                    if start_c < 10:
                        is_system = True
                        
                if is_system:
                    color = "#ff5555"
                elif ratio == 1.0:
                    color = "#55ff55"
                elif ratio > 0.5:
                    color = "#55ffff"
                elif ratio > 0.1:
                    color = "#5555ff"
                elif ratio > 0.0:
                    color = "#888888"
                else:
                    color = "#3a3a3a"
                    
                x1 = c * block_w
                y1 = r * block_h
                x2 = x1 + block_w - 1
                y2 = y1 + block_h - 1
                self.cluster_canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline="#222222", width=1)

    def _update_hex_cursor_status(self, event=None):
        if self.selected_partition is None or not self.mbr_parser:
            return
            
        part = self.mbr_parser.partitions[self.selected_partition]
        parser, fs_type, _ = self._get_volume_parser(self.selected_partition)
        
        txt_widget = event.widget if event else self.txt_hexdump
        if not txt_widget:
            return
            
        try:
            if txt_widget == self.txt_text_view:
                byte_offset = len(txt_widget.get("1.0", "insert"))
                line_text = ""
            else:
                insert_pos = txt_widget.index("insert")
                line_num, col_num = map(int, insert_pos.split("."))
                line_text = txt_widget.get(f"{line_num}.0", f"{line_num}.end")
                
                # Intentar parsear el offset hexadecimal del inicio de la línea
                parts = line_text.split("|")
                if not parts or not parts[0].strip():
                    return
                    
                try:
                    base_offset = int(parts[0].strip(), 16)
                except ValueError:
                    return
                    
                # Calcular el byte relativo dentro de la línea
                byte_in_line = 0
                if len(parts) > 1:
                    pipe_idx = line_text.find("|")
                    if pipe_idx != -1 and col_num > pipe_idx:
                        relative_col = col_num - (pipe_idx + 1)
                        calculated_idx = relative_col // 3
                        if 0 <= calculated_idx < 16:
                            byte_in_line = calculated_idx
                            
                byte_offset = base_offset + byte_in_line
        except Exception:
            return
            
        is_raw_tab = (txt_widget == self.txt_raw_metadata)
        
        clus = "N/A"
        log_sec = "N/A"
        phy_sec = "N/A"
        
        node_id = self.tree.focus()
        node_info = self.tree_nodes.get(node_id) if node_id else None
        
        if not node_info or node_info["type"] == "part" or "SECTOR DE ARRANQUE" in line_text or "VOLCADO HEXADECIMAL DEL SECTOR DE ARRANQUE" in line_text or "VBR" in line_text:
            log_sec = byte_offset // 512
            phy_sec = part.start_lba + log_sec
            clus = "VBR" if log_sec == 0 else "N/A"
        else:
            meta = node_info["meta"]
            
            if is_raw_tab:
                if "NTFS" in fs_type:
                    try:
                        mft_start_offset = part.start_offset + (parser.vbr.mft_start_cluster * parser.vbr.bytes_per_cluster)
                        record_offset = mft_start_offset + (meta["id"] * 1024) + byte_offset
                        phy_sec = record_offset // 512
                        log_sec = (record_offset - part.start_offset) // 512
                        clus = record_offset // parser.vbr.bytes_per_cluster
                    except:
                        pass
                elif "FAT" in fs_type:
                    # Direccionar la Directory Entry dentro del directorio padre
                    try:
                        parent_id = node_info.get("parent_id", 0)
                        start_clust = parent_id
                        # Estimar posición si está disponible la cadena del directorio padre
                        if start_clust > 0:
                            chain = parser.get_fat_chain(start_clust)
                            bytes_per_cluster = parser.get_cluster_size()
                            # Como aproximación didáctica, mapear al inicio del directorio padre
                            if chain:
                                phy_offset = parser.get_cluster_offset(chain[0]) + byte_offset
                                phy_sec = phy_offset // 512
                                log_sec = (phy_offset - part.start_offset) // 512
                                clus = chain[0]
                        elif start_clust == 0 and hasattr(parser, "get_root_dir_offset"):
                            root_offset = parser.get_root_dir_offset()
                            phy_offset = root_offset + byte_offset
                            phy_sec = phy_offset // 512
                            log_sec = (phy_offset - part.start_offset) // 512
                            clus = 0
                    except:
                        pass
            else:
                if "FAT" in fs_type:
                    try:
                        start_clust = meta["id"]
                        if start_clust > 0:
                            chain = parser.get_fat_chain(start_clust)
                            bytes_per_cluster = parser.get_cluster_size()
                            cluster_index = byte_offset // bytes_per_cluster
                            if cluster_index < len(chain):
                                clus = chain[cluster_index]
                                cluster_offset = byte_offset % bytes_per_cluster
                                phy_offset = parser.get_cluster_offset(clus) + cluster_offset
                                phy_sec = phy_offset // 512
                                log_sec = (phy_offset - part.start_offset) // 512
                        elif start_clust == 0 and hasattr(parser, "get_root_dir_offset"):
                            root_offset = parser.get_root_dir_offset()
                            phy_offset = root_offset + byte_offset
                            phy_sec = phy_offset // 512
                            log_sec = (phy_offset - part.start_offset) // 512
                            clus = 0
                    except:
                        pass
                elif "NTFS" in fs_type:
                    try:
                        if not meta.get("is_resident", True) or "data_runs" in meta:
                            chain = []
                            for run in meta.get("data_runs", []):
                                start_lcn = run[1]
                                length = run[0]
                                for offset in range(length):
                                    chain.append(start_lcn + offset)
                            bytes_per_cluster = parser.vbr.bytes_per_cluster
                            cluster_index = byte_offset // bytes_per_cluster
                            if cluster_index < len(chain):
                                clus = chain[cluster_index]
                                cluster_offset = byte_offset % bytes_per_cluster
                                phy_offset = part.start_offset + (clus * bytes_per_cluster) + cluster_offset
                                phy_sec = phy_offset // 512
                                log_sec = (phy_offset - part.start_offset) // 512
                        else:
                            mft_start_offset = part.start_offset + (parser.vbr.mft_start_cluster * parser.vbr.bytes_per_cluster)
                            record_offset = mft_start_offset + (meta["id"] * 1024)
                            phy_offset = record_offset + 150 + byte_offset
                            phy_sec = phy_offset // 512
                            log_sec = (phy_offset - part.start_offset) // 512
                            clus = phy_offset // parser.vbr.bytes_per_cluster
                    except:
                        pass
                elif "Ext4" in fs_type:
                    try:
                        inode_bytes = parser.get_inode(meta["id"])
                        blocks = parser.get_inode_data_blocks(inode_bytes)
                        block_size = parser.superblock.block_size
                        block_index = byte_offset // block_size
                        if block_index < len(blocks):
                            blk = blocks[block_index]
                            block_offset = byte_offset % block_size
                            phy_offset = part.start_offset + (blk * block_size) + block_offset
                            phy_sec = phy_offset // 512
                            log_sec = (phy_offset - part.start_offset) // 512
                            clus = blk
                    except:
                        pass
                        
        self.lbl_hex_status.config(
            text=f"Cursor pos = {byte_offset}; clus = {clus}; log sec = {log_sec}; phy sec = {phy_sec}"
        )

    def _text_formatter(self, data):
        chars = []
        for b in data:
            if (32 <= b < 127) or (160 <= b < 256):
                chars.append(chr(b))
            else:
                chars.append(".")
        return "".join(chars)

    def run(self):
        self.root.mainloop()
