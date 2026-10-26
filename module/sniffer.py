"""Captura y análisis de tráfico de red para PortLock."""

from scapy.all import sniff
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


def analizar_paquete(paquete):
    """Extrae información básica de un paquete de red.

    Args:
        paquete: Paquete de Scapy que se desea analizar.

    Returns:
        dict: Información de direcciones y protocolos detectados.
    """
    resultado = {
        "origen": None,
        "destino": None,
        "protocolos": [],
    }

    if paquete.haslayer(IP):
        resultado["origen"] = paquete[IP].src
        resultado["destino"] = paquete[IP].dst
        resultado["protocolos"].append("IPv4")
    elif paquete.haslayer(IPv6):
        resultado["origen"] = paquete[IPv6].src
        resultado["destino"] = paquete[IPv6].dst
        resultado["protocolos"].append("IPv6")

    if paquete.haslayer(TCP):
        resultado["protocolos"].append("TCP")
    elif paquete.haslayer(UDP):
        resultado["protocolos"].append("UDP")
    elif paquete.haslayer(ICMP):
        resultado["protocolos"].append("ICMP")

    return resultado


def resumir_captura(paquetes):
    """Resume los paquetes capturados y cuenta sus protocolos.

    Args:
        paquetes: Lista de paquetes de Scapy.

    Returns:
        dict: Total de paquetes y cantidad por protocolo.
    """
    resumen = {
        "total": len(paquetes),
        "protocolos": {},
    }

    for paquete in paquetes:
        datos = analizar_paquete(paquete)

        for protocolo in datos["protocolos"]:
            resumen["protocolos"][protocolo] = (
                resumen["protocolos"].get(protocolo, 0) + 1
            )

    return resumen


def capturar_trafico(
    cantidad=10,
    tiempo=10,
    filtro=None,
    interfaz=None,
):
    """Captura una cantidad limitada de paquetes de red.

    Args:
        cantidad (int): Número máximo de paquetes.
        tiempo (int): Duración máxima en segundos.
        filtro (str): Filtro BPF opcional.
        interfaz (str): Interfaz de red opcional.

    Returns:
        list: Paquetes capturados.

    Raises:
        ValueError: Si los límites indicados no son válidos.
        RuntimeError: Si Scapy no puede iniciar la captura.
    """
    if not isinstance(cantidad, int) or isinstance(cantidad, bool):
        raise ValueError("La cantidad debe ser un entero.")
    if not isinstance(tiempo, int) or isinstance(tiempo, bool):
        raise ValueError("El tiempo debe ser un entero.")
    if cantidad <= 0 or tiempo <= 0:
        raise ValueError(
            "La cantidad y el tiempo deben ser positivos."
        )

    try:
        paquetes = sniff(
            count=cantidad,
            timeout=tiempo,
            filter=filtro,
            iface=interfaz,
            store=True,
        )
        return list(paquetes)
    except (Scapy_Exception, OSError, ValueError) as error:
        raise RuntimeError(
            f"No se pudo capturar el tráfico: {error}"
        ) from error
