"""Módulo pcap_analyzer.

Proporciona funciones para el análisis forense de archivos de captura de
tráfico.
"""

from scapy.all import rdpcap
from scapy.error import Scapy_Exception


def leer_archivo_pcap(ruta_archivo):
    """Lee un archivo pcap y devuelve la lista de paquetes capturados.

    Args:
        ruta_archivo (str): Ruta al archivo .pcap a analizar.

    Returns:
        list: Lista de paquetes de Scapy o lista vacía en caso de error.
    """
    try:
        paquetes = rdpcap(ruta_archivo)
        print(f"[+] Se leyeron {len(paquetes)} paquetes exitosamente.")
        return paquetes
    except FileNotFoundError:
        print(f"[-] Error: El archivo '{ruta_archivo}' no fue encontrado.")
        return []
    except Scapy_Exception as e:
        print(f"[-] Error de Scapy al procesar el archivo: {e}")
        return []


def filtrar_por_protocolo(paquetes, protocolo):
    """Filtra los paquetes capturados según una capa o protocolo específico.

    Args:
        paquetes (list): Lista de paquetes de Scapy.
        protocolo (str): Nombre de la capa a filtrar (ej. 'IP', 'TCP').

    Returns:
        list: Subconjunto de paquetes que contienen el protocolo.
    """
    try:
        filtrados = [pkt for pkt in paquetes if pkt.haslayer(protocolo)]
        print(f"[+] Se encontraron {len(filtrados)} paquetes del "
              f"protocolo {protocolo}.")
        return filtrados
    except Exception as e:
        print(f"[-] Error al filtrar paquetes por protocolo: {e}")
        return []


def generar_resumen_trafico(paquetes):
    """Imprime un resumen básico de las direcciones IP origen y destino.

    Args:
        paquetes (list): Lista de paquetes de Scapy.
    """
    try:
        if not paquetes:
            print("[-] No hay paquetes disponibles para generar el resumen.")
            return

        print("\n--- Resumen de Tráfico IP ---")
        for i, pkt in enumerate(paquetes[:5]):
            if pkt.haslayer('IP'):
                print(f"Paquete {i + 1}: {pkt['IP'].src} -> {pkt['IP'].dst}")
    except Exception as e:
        print(f"[-] Error al generar el resumen de tráfico: {e}")
