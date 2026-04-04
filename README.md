# procesado_paquetes
Programa muy sencillo que simula el procesamiento de paquetes en una torre de protocolos. Solo reconoce los protocolos Ethernet, IPv4, TCP, y HTTP. Si no se reconoce un protocolo, se termina el procesamiento de ese paquete y se continúa con el siguiente. 

Requiere la instalación de las librerías python:

```
pip install pyshark scapy
```

## Utilización
Dado un fichero de entrada, que puede ser .pcap o .txt (con paquetes línea por línea en hexadecimal), hace una simulación del procesamiento del paquete y genera un fichero output.txt (si la entrada era .pcap) o output.pcap (si la entrada era .txt). El fichero generado añade la FCS Ethernet a las tramas en el fichero de salida, si no la tenían.


Uso:

```
python torre-protocolos_UI_progresivo_v3.py [fichero.pcap ó fichero.txt]
```

Se incluyen capturas de ejemplo en el directorio capturas.
