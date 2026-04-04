import pyshark
import tkinter as tk
from tkinter import scrolledtext
import argparse
from scapy.all import Ether, Raw, wrpcap
import binascii
from pathlib import Path

nivel=2
indice=0
#btn_avanzar2 = None


class GInterface:
        
    def __init__(self):
        self.ventana = tk.Tk()
        self.ventana.title("Análisis de Paquetes")
        
        # Configurar el tamaño de la ventana
        self.ventana.geometry("680x790")
        # Crear un Frame para dividir la ventana
        frame = tk.Frame(self.ventana)
        frame.pack(fill=tk.BOTH, expand=True)
    
        # Crear cuatro áreas de texto para mostrar la información de cada capa
        self.text_area_1 = scrolledtext.ScrolledText(frame, height=10, width=80, bg='lightcoral')
        self.text_area_1.grid(row=3, column=0, padx=5, pady=5)

        self.text_area_2 = scrolledtext.ScrolledText(frame, height=10, width=80, bg='lightgreen')
        self.text_area_2.grid(row=2, column=0, padx=5, pady=5) 
        self.text_area_3 = scrolledtext.ScrolledText(frame, height=10, width=80, bg='lightyellow')
        self.text_area_3.grid(row=1, column=0, padx=5, pady=5)

        self.text_area_4 = scrolledtext.ScrolledText(frame, height=10, width=80, bg='lightblue')
        self.text_area_4.grid(row=0, column=0, padx=5, pady=5)
    
        # =========================
        # Diccionario de áreas
        # =========================
        self.areas = {
            "ta1": self.text_area_1,
            "ta2": self.text_area_2,
            "ta3": self.text_area_3,
            "ta4": self.text_area_4
        }

    # Función que escribe en GUI
    def escribir_en_gui(self, texto, area):
        if area in self.areas:
            area = self.areas[area]
            area.insert(tk.END, texto)

    # Función para limpiar todas las áreas de texto
    def limpiar_areas(self):
        for area in self.areas.values():
            area.delete("1.0", tk.END)



def comprobar_extension(nombre_fichero, extension):
    return Path(nombre_fichero).suffix.lower() == extension.lower()

def leer_captura(file):
    num_paquetes = 0
    # Comprobar archivo de entrada
    if comprobar_extension(file, ".pcap"):
        # Leer los paquetes del archivo pcap
        cap = pyshark.FileCapture(file, include_raw=True, use_json=True)
        num_paquetes=pcap_a_hex(cap, "output.txt") 
        print(f"Archivo .pcap leído, convertido a .txt con {num_paquetes} paquetes")
        #for pkt in cap:
        #    num_paquetes += 1
        return { "cap": cap, "num_paquetes": num_paquetes }
    elif comprobar_extension(file, ".txt"):
        # Lo convertimos a pcap
        output_pcap = "output.pcap"        
        hex_a_pcap(file, output_pcap)
        # Leer los paquetes del archivo pcap convertido
        cap = pyshark.FileCapture(output_pcap, include_raw=True, use_json=True) 
        # num_paquetes = len(list(cap))   
        for pkt in cap:
            num_paquetes += 1
        return { "cap": cap, "num_paquetes": num_paquetes }
    else:
        raise ValueError("El archivo no tiene la extensión .pcap ni .txt")

def pcap_a_hex(cap, output_txt):
    count = 0
    with open(output_txt, 'w') as f:
        for pkt in cap:
            try:
                raw_hex = pkt.frame_raw.value  # hex string
                if not hasattr(pkt.eth, 'fcs'):
                    fcs_value = calcular_fcs(raw_hex)
                    raw_hex += fcs_value  # Añadir el FCS al final de la trama
                count += 1
                f.write(raw_hex + '\n')
            except AttributeError:
                # Paquete sin raw (raro pero posible)
                continue
    f.close()        
    return count

def hex_a_pcap(input_txt, output_pcap):
    paquetes = []

    with open(input_txt, 'r') as f:
        for linea in f:
            hex_str = linea.strip() 
            if hex_str:
                raw_bytes = bytes.fromhex(hex_str)
                len_trama = len(raw_bytes)
                len_ip = int.from_bytes(raw_bytes[17:18], byteorder='big')
                #print(f"Longitud de trama: {len_trama} hex chars, Longitud IP: {len_ip} bytes")
                if len_ip + 14 == len_trama: # Heusrístico para detectar si falta FCS, en ese caso lo añadimos
                    fcs = calcular_fcs(hex_str)
                    hex_str += fcs  # Añadir el FCS al final de la trama
                    raw_bytes = bytes.fromhex(hex_str)
                try:
                    pkt = Ether(raw_bytes)  # intenta decodificar capas
                except:
                    pkt = Raw(load=raw_bytes)  # fallback

                paquetes.append(pkt)

    wrpcap(output_pcap, paquetes)

def calcular_fcs(hex_str):
    data = bytes.fromhex(hex_str)
    fcs = binascii.crc32(data) & 0xffffffff
    return format(fcs, '08x')


# Función para decodificar y mostrar los paquetes en la interfaz
def procesar_paquetes(pkts, gui):
    
    paquetes = pkts["cap"]
    num_paquetes = pkts["num_paquetes"]
    
    global nivel
    global indice
    btn_avanzar2=None

    # Limpiar las áreas de texto antes de mostrar el siguiente paquete
    gui.limpiar_areas()

    btn_avanzar.config(state=tk.DISABLED) # Desactivar el botón mientras se procesan las cabeceras  
    paquete = paquetes[indice]
    gui.ventana.title(f"Análisis de Paquetes - Procesando Paquete {paquete.number} de {num_paquetes} paquetes")
    btn_avanzar2 = tk.Button(gui.ventana, text="Procesar siguiente cabecera",  bg='orange', fg='black', font=('Arial', 12), command=lambda: procesado_cabeceras(paquete, num_paquetes, btn_avanzar2, gui))
    btn_avanzar2.pack(pady=(0,10))

    indice += 1  
    
    if indice >= num_paquetes:
        btn_avanzar.destroy() # No hay más paquetes, destruir botón
        #btn_avanzar.config(state=tk.DISABLED)  
        
    #if i < num_paquetes: 
    #    ventana.after(5000, lambda: procesar_paquetes(paquetes, i))
    

def procesado_cabeceras(paquete, num_paquetes, btn_avanzar2, gui):
    global nivel
    global indice

    # Mostrar la capa Ethernet (si existe)
    if nivel==2 and hasattr(paquete, 'eth'):
        texto=f"Procesando paquete a nivel  Ethernet: \n"
        if hasattr(paquete.eth, 'fcs'):
            fcs_value = paquete.eth.fcs
            try:

                # Obtener frame completo en hex
                raw=paquete.frame_raw.value  # trama completa en hexadecimal
            
                # Si la captura incluye FCS, los últimos 4 bytes son el FCS
                frame_sin_fcs = raw[:-8]  # quitar últimos 4 bytes (8 hex chars)
                fcs_capturado = raw[-8:]

                fcs_calculado = calcular_fcs(frame_sin_fcs)
                texto += f"\n    FCS capturado en la trama: {fcs_value}"
                texto += f"\n    FCS calculado a partir de la trama: 0x{fcs_calculado}"
                if fcs_capturado.lower() == fcs_calculado.lower():
                    texto += "\n    FCS en trama correcto\n"
                else:
                    texto += "\n    FCS en trama incorrecto\n"
                    nivel=6

            except AttributeError:
                texto += f"\n    No se puede comprobar FCS en la trama"
        texto += f"\n    Destino: {paquete.eth.dst}, hemos llegado al destino en el enlace\n"
        if paquete.eth.type== '0x0800':
            texto += f"\n    Campo EtherType: IPv4 (0x0800)-> Enviamos a la capa IP\n"
        else:
            texto += f"\n    Campo EtherType: No es IPv4 (0x0800), es {paquete.eth.type} -> Fin de procesamiento\n"
            nivel=6
        gui.escribir_en_gui(texto, "ta1")
    # Mostrar la capa IP (si existe)
    if nivel==3 and hasattr(paquete, 'ip'):
        texto=f"Procesando paquete a nivel IP: \n"
        texto+=f"\n    IP: {paquete.ip.src} -> {paquete.ip.dst}, hemos llegado al destino\n"
        if paquete.ip.proto == '6':
            texto+=f"\n    Campo de protocolo de la cabecera IP: TCP ({paquete.ip.proto})-> Enviamos a la capa TCP\n"  
        else:
            texto+=f"\n    Campo de protocolo de la cabecera IP: No es TCP, es {paquete.ip.proto} -> Fin de procesamiento\n"
            nivel=6
        gui.escribir_en_gui(texto, "ta2")
    # Mostrar la capa TCP (si existe)
    if nivel==4 and hasattr(paquete, 'tcp'):
        texto=f"Procesando paquete a nivel TCP: \n"
        if hasattr(paquete.tcp, 'len') and int(paquete.tcp.len) > 0:
            texto+=f"\n    TCP: {paquete.tcp.srcport} -> {paquete.tcp.dstport}\n"
            texto+=f"\n    Entregamos datos a socket\n"
        else:
            texto+=f"\n    TCP: {paquete.tcp.srcport} -> {paquete.tcp.dstport}\n"
            texto+=f"\n    No hay datos en el segmento TCP, fin de procesamiento\n"
            nivel=6
        gui.escribir_en_gui(texto, "ta3")
    # Mostrar la capa APP (si existe)
    if nivel==5 and hasattr(paquete, 'http'):
        texto=f"Procesando paquete a nivel HTTP: \n"
        texto+=f"\n    Recibidos datos en el socket, interpretando como HTTP\n"
        #texto+=f"{paquete.http.field_names}\n"
        if 'request' in paquete.http.field_names:
            uri=paquete.http.get_field("request.full_uri")
            texto+=f"\n    HTTP request: {uri}\n"
            #texto=f"  HTTP: {paquete.http.request_method} {paquete.http.request_uri}\n"
        elif '1 200 OK\\r\\n' in paquete.http.field_names and 'file_data' in paquete.http.field_names: 
            texto=texto+f"\n    HTTP: 200 OK -> Se guarda contenido en salida{indice}.html\n"
            with open("salida{indice}.html", "wb") as f:
                f.write(bytes.fromhex(paquete.http.file_data.replace(':', '')))
        else:
            texto=texto+f"\n  HTTP: No es una petición ni una respuesta 200 OK con datos -> Fin de procesamiento\n"
            nivel=6
        #elif hasattr(paquete.http, 'file_data'):
        #    texto=texto+f"  HTTP: Data\n"
        #    with open("salida.html", "wb") as f:
        #        f.write(bytes.fromhex(paquete.http.file_data.replace(':', '')))
        gui.escribir_en_gui(texto, "ta4")
    if nivel==5 and indice < num_paquetes:
        btn_avanzar.config(state=tk.NORMAL)  # Volver a habilitar el botón después de procesar el paquete y si hay más paquetes
        btn_avanzar2.destroy()  # Eliminar el botón de procesar cabeceras después de procesar el paquete
        nivel=1
    elif nivel==5 and indice >= num_paquetes:
        btn_avanzar2.destroy()  # Eliminar el botón de procesar cabeceras después de procesar el último paquete
    
    if nivel == 6:
        btn_avanzar2.destroy()  # Eliminar el botón de procesar cabeceras, fin de procesamiento por error
        if indice < num_paquetes:
            btn_avanzar.config(state=tk.NORMAL)  # Volver a habilitar el botón después de procesar el paquete y si hay más paquetes
            nivel=1
    
    nivel+=1
    #if nivel <= 5:   
        #ventana.after(1000, lambda: procesado_cabeceras(paquete, nivel+1))    
        #text_area_1.insert(tk.END, "-" * 40 + "\n")        
    
    


parser = argparse.ArgumentParser(description="Leer fichero")
parser.add_argument("fichero", help="Nombre del fichero a procesar")

args = parser.parse_args()
    
gui=GInterface()

# Leer el fichero .pcap o .txt con los paquetes
pkts=leer_captura(args.fichero)
# Crear un botón para avanzar en el bucle
btn_avanzar = tk.Button(gui.ventana, text="Procesar siguiente paquete", bg='green', fg='black', font=('Arial', 12), command=lambda: procesar_paquetes(pkts, gui))
btn_avanzar.pack(pady=(0,10))
gui.ventana.mainloop()

