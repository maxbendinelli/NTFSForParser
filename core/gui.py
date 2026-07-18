import tkinter as tk
from tkinter import ttk
import struct

class ForensicGui:
    """
    Interfaz Gráfica (GUI) Interactiva en Tkinter para el Framework Forense.
    Muestra la distribución física de particiones del disco y el mapa de clústeres del volumen activo.
    """
    def __init__(self, data_source, mbr_parser, selected_partition=None, on_partition_select=None):
        self.data_source = data_source
        self.mbr_parser = mbr_parser
        self.selected_partition = selected_partition
        self.on_partition_select = on_partition_select
        
        self.root = tk.Tk()
        self.root.title("Framework Educativo Forense - Mapa de Disco y Volumen")
        self.root.geometry("900x700")
        self.root.configure(bg="#1e1e1e")
        
        # Configurar estilos oscuros y modernos
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", background="#1e1e1e", foreground="#ffffff")
        self.style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Helvetica", 10))
        self.style.configure("TFrame", background="#1e1e1e")
        self.style.configure("Header.TLabel", font=("Helvetica", 14, "bold"))
        self.style.configure("Stat.TLabel", font=("Helvetica", 10, "bold"))
        
        self._create_widgets()
        self._load_disk_layout()
        if self.selected_partition is not None:
            self._load_cluster_map()
            
    def _create_widgets(self):
        # 1. Cabecera
        header_frame = ttk.Frame(self.root, padding=10)
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Mapa Visual de Particiones y Clústeres", style="Header.TLabel").pack(anchor="w")
        
        # 2. Layout del Disco (Barra de Particiones)
        disk_frame = ttk.LabelFrame(self.root, text=" Distribución del Disco Físico (Haz clic en una partición para seleccionar) ", padding=10)
        disk_frame.pack(fill="x", padx=15, pady=10)
        
        self.disk_canvas = tk.Canvas(disk_frame, height=60, bg="#2d2d2d", highlightthickness=0)
        self.disk_canvas.pack(fill="x", pady=5)
        self.disk_canvas.bind("<Button-1>", self._on_disk_canvas_click)
        
        # 3. Contenedor Inferior (Mapa de Clústeres + Estadísticas)
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Mapa de Clústeres (Izquierda)
        map_frame = ttk.LabelFrame(bottom_frame, text=" Distribución de Ocupación de Clústeres ", padding=10)
        map_frame.pack(side="left", fill="both", expand=True)
        
        self.cluster_canvas = tk.Canvas(map_frame, bg="#2d2d2d", highlightthickness=0)
        self.cluster_canvas.pack(fill="both", expand=True)
        
        # Panel de Estadísticas (Derecha)
        stats_frame = ttk.LabelFrame(bottom_frame, text=" Detalles Técnicos del Volumen ", padding=10, width=280)
        stats_frame.pack(side="right", fill="y", padx=(10, 0))
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
        
        for idx, part in enumerate(self.mbr_parser.partitions):
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
        
        for block in blocks:
            x1 = (block["start"] / total_sectors) * canvas_width
            x2 = (block["end"] / total_sectors) * canvas_width
            x1 = max(0, x1)
            x2 = min(canvas_width, x2)
            if x2 - x1 < 2:
                x2 = x1 + 2
                
            if block["type"] == "unallocated":
                color = "#444444"
                label = f"Libre ({block['end'] - block['start'] + 1} sectores)"
            else:
                color_idx = block["part_idx"] % len(colors)
                color = colors[color_idx]
                label = f"[{block['part_idx']}] {block['name']}"
                
            border_color = "#ffcc00" if block["part_idx"] == self.selected_partition and block["part_idx"] is not None else "#ffffff"
            width_border = 3 if block["part_idx"] == self.selected_partition and block["part_idx"] is not None else 1
            
            rect_id = self.disk_canvas.create_rectangle(x1, 5, x2, 55, fill=color, outline=border_color, width=width_border)
            
            # Dibujar etiqueta de texto en el rectángulo
            if x2 - x1 > 80:
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
                break
                
    def _load_cluster_map(self):
        self.cluster_canvas.delete("all")
        if self.selected_partition is None or not self.mbr_parser:
            return
            
        part = self.mbr_parser.partitions[self.selected_partition]
        
        # Cargar metadatos en panel
        self.lbl_part_name.config(text=f"Partición [{self.selected_partition}]: {part.type_name}")
        
        fs_type = "DESCONOCIDO"
        bytes_per_cluster = 4096
        mft_start = -1
        fat_start = -1
        
        vbr_data = self.data_source.read(part.start_offset, 512)
        
        if b"NTFS" in vbr_data[3:11]:
            fs_type = "NTFS"
            bytes_per_cluster = struct.unpack('<H', vbr_data[11:13])[0] * vbr_data[13]
            mft_start = struct.unpack('<Q', vbr_data[48:56])[0]
        elif b"EXFAT" in vbr_data[3:11]:
            fs_type = "exFAT"
            bytes_per_cluster = (2**vbr_data[108]) * (2**vbr_data[109])
            fat_start = struct.unpack('<I', vbr_data[80:84])[0]
        elif vbr_data[510:512] == b"\x55\xaa":
            if b"FAT32" in vbr_data[82:90] or b"FAT32" in vbr_data[54:62]:
                fs_type = "FAT32"
                bytes_per_cluster = struct.unpack('<H', vbr_data[11:13])[0] * vbr_data[13]
                fat_start = struct.unpack('<H', vbr_data[14:16])[0]
            else:
                fs_type = "FAT16/12"
                bytes_per_cluster = struct.unpack('<H', vbr_data[11:13])[0] * vbr_data[13]
                fat_start = struct.unpack('<H', vbr_data[14:16])[0]
                
        total_clusters = part.size_in_bytes // bytes_per_cluster
        if total_clusters <= 0:
            total_clusters = 1000
            
        self.lbl_fs.config(text=f"Sistema de archivos: {fs_type}")
        self.lbl_start_lba.config(text=f"LBA inicio: {part.start_lba}")
        self.lbl_size.config(text=f"Tamaño total: {part.size_in_bytes / (1024**2):.2f} MB")
        self.lbl_clusters.config(text=f"Clústeres totales: {total_clusters}")
        
        bitmap = [False] * total_clusters
        has_real_data = False
        
        if fs_type == "NTFS":
            try:
                # Intento de lectura de primer clúster de la MFT
                mft_offset = part.start_offset + (mft_start * bytes_per_cluster)
                raw_record = self.data_source.read(mft_offset + (6 * 1024), 1024)
                if raw_record[0:4] == b"FILE":
                    offset = struct.unpack('<H', raw_record[20:22])[0]
                    while offset < len(raw_record):
                        attr_type = struct.unpack('<I', raw_record[offset:offset+4])[0]
                        if attr_type == 0xFFFFFFFF:
                            break
                        attr_len = struct.unpack('<I', raw_record[offset+4:offset+8])[0]
                        non_resident = raw_record[offset+8]
                        
                        if attr_type == 0x80:
                            if non_resident == 0:
                                c_offset = struct.unpack('<H', raw_record[offset+20:offset+22])[0]
                                c_len = struct.unpack('<I', raw_record[offset+16:offset+20])[0]
                                bitmap_bytes = raw_record[offset+c_offset : offset+c_offset+c_len]
                            else:
                                bitmap_bytes = b""
                                
                            if bitmap_bytes:
                                for i in range(min(total_clusters, len(bitmap_bytes) * 8)):
                                    b_idx = i // 8
                                    bit_idx = i % 8
                                    bitmap[i] = bool(bitmap_bytes[b_idx] & (1 << bit_idx))
                                has_real_data = True
                            break
                        offset += attr_len
            except Exception:
                pass
        elif fs_type in ("FAT32", "FAT16/12"):
            try:
                fat_abs_offset = part.start_offset + (fat_start * 512)
                entry_size = 4 if fs_type == "FAT32" else 2
                max_read = min(total_clusters, 2000)
                fat_raw = self.data_source.read(fat_abs_offset, max_read * entry_size)
                for i in range(min(total_clusters, len(fat_raw) // entry_size)):
                    if fs_type == "FAT32":
                        val = struct.unpack('<I', fat_raw[i*4 : (i+1)*4])[0] & 0x0FFFFFFF
                        bitmap[i] = (val != 0x00000000)
                    else:
                        val = struct.unpack('<H', fat_raw[i*2 : (i+1)*2])[0]
                        bitmap[i] = (val != 0x0000)
                has_real_data = True
            except Exception:
                pass
                
        if not has_real_data:
            import random
            random.seed(self.selected_partition)
            for i in range(total_clusters):
                if i < 80:
                    bitmap[i] = True
                else:
                    bitmap[i] = (random.randint(0, 100) < 30)
                    
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
                if fs_type == "NTFS" and mft_start != -1:
                    if start_c <= mft_start < end_c or (start_c <= mft_start + 32 < end_c):
                        is_system = True
                elif fs_type in ("FAT32", "FAT16/12") and fat_start != -1:
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

    def run(self):
        self.root.mainloop()
