"""Módulo scanner: escaneo básico de puertos TCP con Scapy."""

from scapy.all import IP, TCP, sr1


def validar_puerto(puerto):
    """Comprueba que el puerto sea un número entre 1 y 65535.

    Args:
        puerto (int): Número de puerto a validar.

    Returns:
        bool: True si el puerto es válido, False en caso contrario.
    """
    return isinstance(puerto, int) and 1 <= puerto <= 65535


def escanear_puerto(ip, puerto):
    """Envía un paquete SYN a un puerto y dice si está abierto.

    Args:
        ip (str): Dirección IP del objetivo.
        puerto (int): Puerto TCP a probar.

    Returns:
        bool: True si el puerto está abierto, False si no.
    """
    if not validar_puerto(puerto):
        return False
    try:
        paquete = IP(dst=ip) / TCP(dport=puerto, flags="S")
        respuesta = sr1(paquete, timeout=1, verbose=0)
    except PermissionError:
        print("Error: ejecuta el programa como administrador (sudo).")
        return False
    if respuesta is None or not respuesta.haslayer(TCP):
        return False
    return respuesta[TCP].flags == "SA"


def escanear_rango(ip, inicio, fin):
    """Escanea un rango de puertos y devuelve los que están abiertos.

    Args:
        ip (str): Dirección IP del objetivo.
        inicio (int): Primer puerto del rango.
        fin (int): Último puerto del rango (inclusive).

    Returns:
        list: Lista con los números de puerto abiertos.
    """
    abiertos = []
    for puerto in range(inicio, fin + 1):
        if escanear_puerto(ip, puerto):
            abiertos.append(puerto)
    return abiertos
