"""Punto de entrada CLI para la herramienta PortLock."""

import argparse
import json
import sys

from module.network_utils import (
    preparar_objetivo,
    validar_puerto,
    validar_rango_puertos,
)
from module.port_scanner import validate_target, scan_port, scan_ports
from module.scanner import escanear_rango
from module.sniffer import capturar_trafico, resumir_captura
from module.pcap_analyzer import (
    leer_archivo_pcap,
    filtrar_por_protocolo,
    generar_resumen_trafico,
)
from module.informes import guardar_reporte


def guardar_resultado(args, parametros, resultados, errores=None):
    """Guarda el resultado en el formato y la ruta indicados por CLI."""
    ruta = args.output or f"reporte_{args.comando}.{args.formato}"
    datos = {
        "parametros": parametros,
        "resultados": resultados,
        "errores": errores or [],
    }

    try:
        guardar_reporte(datos, ruta, args.formato)
    except (ValueError, OSError) as error:
        print(f"[!] No se pudo generar el reporte: {error}", file=sys.stderr)
        return False
    return True


def validar_objetivo(entrada):
    """Resuelve el objetivo y comprueba que sea una dirección IPv4."""
    objetivo = preparar_objetivo(entrada)
    ip_objetivo = validate_target(objetivo)
    if ip_objetivo is None:
        raise ValueError("El objetivo debe ser una dirección IPv4 válida.")
    return str(ip_objetivo)


def ejecutar_scan(args):
    try:
        objetivo = validar_objetivo(args.target)
        puerto = validar_puerto(args.port)
    except ValueError as error:
        print(f"[!] {error}", file=sys.stderr)
        return 2

    abierto = scan_port(objetivo, puerto)
    estado = "ABIERTO" if abierto else "CERRADO"
    print(f"[+] {objetivo}:{puerto} está {estado.lower()}.")

    guardar_resultado(
        args,
        {"objetivo": objetivo, "puerto": puerto, "tipo": "TCP por sockets"},
        [{"puerto": puerto, "estado": estado}],
    )
    return 0


def ejecutar_scan_range(args):
    try:
        objetivo = validar_objetivo(args.target)
        inicio, fin = validar_rango_puertos(f"{args.start_port}-{args.end_port}")
    except ValueError as error:
        print(f"[!] {error}", file=sys.stderr)
        return 2

    abiertos = scan_ports(objetivo, inicio, fin)
    print(f"[+] Puertos abiertos: {abiertos}")

    guardar_resultado(
        args,
        {
            "objetivo": objetivo,
            "puerto_inicial": inicio,
            "puerto_final": fin,
            "tipo": "TCP por sockets",
        },
        [{"puerto": puerto, "estado": "ABIERTO"} for puerto in abiertos],
    )
    return 0


def ejecutar_syn(args):
    try:
        objetivo = validar_objetivo(args.target)
        inicio, fin = validar_rango_puertos(f"{args.start_port}-{args.end_port}")
    except ValueError as error:
        print(f"[!] {error}", file=sys.stderr)
        return 2

    abiertos = escanear_rango(objetivo, inicio, fin)
    print(f"[+] Puertos abiertos encontrados: {abiertos}")

    guardar_resultado(
        args,
        {
            "objetivo": objetivo,
            "tipo": "SYN con Scapy",
            "puerto_inicial": inicio,
            "puerto_final": fin,
        },
        [{"puerto": puerto, "estado": "ABIERTO"} for puerto in abiertos],
    )
    return 0


def ejecutar_sniffer(args):
    try:
        paquetes = capturar_trafico(
            cantidad=args.count,
            tiempo=args.timeout,
            filtro=args.filter,
            interfaz=args.interface,
        )
    except (ValueError, RuntimeError) as error:
        print(f"[!] Error en el sniffer: {error}", file=sys.stderr)
        return 2

    if not paquetes:
        print("[-] No se capturaron paquetes.")
        resultados = []
        errores = ["No se capturaron paquetes."]
        resumen = {"total": 0, "protocolos": {}}
    else:
        resumen = resumir_captura(paquetes)
        print(f"[+] Total de paquetes: {resumen['total']}")
        print(f"[+] Protocolos: {resumen['protocolos']}")
        resultados = [resumen]
        errores = []

    guardar_resultado(
        args,
        {
            "tipo": "Captura de tráfico de red",
            "cantidad_maxima": args.count,
            "tiempo_limite": args.timeout,
            "filtro": args.filter,
            "interfaz": args.interface,
        },
        resultados,
        errores,
    )
    return 0


def ejecutar_pcap(args):
    paquetes = leer_archivo_pcap(args.file)
    if not paquetes:
        print("[-] No se pudo analizar el archivo PCAP.", file=sys.stderr)
        return 1

    generar_resumen_trafico(paquetes)
    resultados = [
        {"paquete": indice + 1, "resumen": paquete.summary()}
        for indice, paquete in enumerate(paquetes[:5])
    ]

    guardar_resultado(
        args,
        {
            "tipo": "Análisis de archivo PCAP",
            "archivo": args.file,
            "total_paquetes": len(paquetes),
        },
        resultados,
    )
    return 0


def ejecutar_pcap_filter(args):
    paquetes = leer_archivo_pcap(args.file)
    if not paquetes:
        print("[-] No se pudo leer el archivo PCAP.", file=sys.stderr)
        return 1

    filtrados = filtrar_por_protocolo(paquetes, args.protocol.upper())
    if filtrados:
        generar_resumen_trafico(filtrados)

    resultados = [
        {
            "paquete": indice + 1,
            "protocolo": args.protocol.upper(),
            "resumen": paquete.summary(),
        }
        for indice, paquete in enumerate(filtrados[:5])
    ]

    if not filtrados:
        print("[-] No se encontraron paquetes para ese protocolo.")

    guardar_resultado(
        args,
        {
            "tipo": "Filtrado de paquetes PCAP",
            "archivo": args.file,
            "protocolo": args.protocol.upper(),
            "total_paquetes_filtrados": len(filtrados),
        },
        resultados,
    )
    return 0


def agregar_opciones_reporte(parser, comando):
    parser.add_argument(
        "--format",
        dest="formato",
        choices=("json", "csv", "txt"),
        default="json",
        help="Formato del reporte (predeterminado: json).",
    )
    parser.add_argument(
        "--output",
        help=f"Ruta del reporte. Predeterminado: reporte_{comando}.<formato>.",
    )


def crear_parser():
    parser = argparse.ArgumentParser(
        prog="portlock",
        description="PortLock: herramienta de análisis y diagnóstico de red.",
    )
    subparsers = parser.add_subparsers(
        dest="comando",
        required=True,
        help="Operaciones disponibles",
    )

    scan = subparsers.add_parser("scan", help="Comprobar un puerto TCP.")
    scan.add_argument("--target", required=True, help="IP o dominio objetivo.")
    scan.add_argument("--port", required=True, type=int, help="Puerto TCP (1-65535).")
    agregar_opciones_reporte(scan, "scan")
    scan.set_defaults(func=ejecutar_scan)

    scan_range = subparsers.add_parser(
        "scan-range", help="Comprobar un rango de puertos TCP."
    )
    scan_range.add_argument("--target", required=True, help="IP o dominio objetivo.")
    scan_range.add_argument("--start-port", required=True, type=int)
    scan_range.add_argument("--end-port", required=True, type=int)
    agregar_opciones_reporte(scan_range, "scan_range")
    scan_range.set_defaults(func=ejecutar_scan_range)

    syn = subparsers.add_parser("syn", help="Ejecutar escaneo SYN con Scapy.")
    syn.add_argument("--target", required=True, help="IP o dominio objetivo.")
    syn.add_argument("--start-port", required=True, type=int)
    syn.add_argument("--end-port", required=True, type=int)
    agregar_opciones_reporte(syn, "syn")
    syn.set_defaults(func=ejecutar_syn)

    sniffer = subparsers.add_parser("sniffer", help="Capturar tráfico de red.")
    sniffer.add_argument("--count", type=int, default=10, help="Máximo de paquetes.")
    sniffer.add_argument("--timeout", type=int, default=10, help="Tiempo límite en segundos.")
    sniffer.add_argument("--filter", dest="filter", help="Filtro BPF opcional.")
    sniffer.add_argument("--interface", help="Interfaz de red opcional.")
    agregar_opciones_reporte(sniffer, "sniffer")
    sniffer.set_defaults(func=ejecutar_sniffer)

    pcap = subparsers.add_parser("pcap", help="Analizar un archivo PCAP.")
    pcap.add_argument("--file", required=True, help="Ruta del archivo PCAP.")
    agregar_opciones_reporte(pcap, "pcap")
    pcap.set_defaults(func=ejecutar_pcap)

    pcap_filter = subparsers.add_parser(
        "pcap-filter", help="Filtrar un PCAP por protocolo."
    )
    pcap_filter.add_argument("--file", required=True, help="Ruta del archivo PCAP.")
    pcap_filter.add_argument(
        "--protocol", required=True, help="Capa o protocolo, por ejemplo TCP o UDP."
    )
    agregar_opciones_reporte(pcap_filter, "pcap_filter")
    pcap_filter.set_defaults(func=ejecutar_pcap_filter)

    return parser


def main():
    parser = crear_parser()
    args = parser.parse_args()
    return


if __name__ == "__main__":
    raise SystemExit(main())
