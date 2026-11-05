"""PortLock — Herramienta de ciberseguridad defensiva.

Reconocimiento, escaneo de puertos y auditoría de redes mediante sockets
desde la línea de comandos.

Uso:
    from module import escanear_puerto, guardar_reporte, preparar_objetivo
    from module.network_utils import validar_puerto
"""

__version__ = "0.5.0"
__author__ = "Equipo PortLock"

from . import network_utils
from .network_utils import (
    preparar_objetivo,
    validar_archivo_salida,
    validar_ip,
    validar_puerto,
    validar_rango_puertos,
)
from .pcap_analyzer import (
    filtrar_por_protocolo,
    generar_resumen_trafico,
    leer_archivo_pcap,
)
from .port_scanner import main, scan_port, scan_ports, validate_target
from .reportes import guardar_reporte
from .scanner import escanear_puerto, escanear_rango
from .sniffer import (
    analizar_paquete,
    capturar_trafico,
    resumir_captura,
)

__all__ = [
    "main",
    "scan_port",
    "scan_ports",
    "validate_target",
    "escanear_puerto",
    "escanear_rango",
    "network_utils",
    "preparar_objetivo",
    "validar_ip",
    "validar_puerto",
    "validar_rango_puertos",
    "validar_archivo_salida",
    "filtrar_por_protocolo",
    "generar_resumen_trafico",
    "leer_archivo_pcap",
    "analizar_paquete",
    "capturar_trafico",
    "resumir_captura",
    "guardar_reporte",
]
