"""Punto de entrada principal (CLI) para la herramienta de ciberseguridad PortLock."""

import argparse
import sys
import json
from datetime import datetime

try:
    from module.network_utils import preparar_objetivo
    from module.port_scanner import validate_target, scan_port, scan_ports
    from module.scanner import escanear_puerto, escanear_rango
    from module.sniffer import capturar_trafico, resumir_captura
    from module.pcap_analyzer import (
        leer_archivo_pcap,
        filtrar_por_protocolo,
        generar_resumen_trafico,
    )
except ImportError:
    from portlock.module.network_utils import preparar_objetivo
    from portlock.module.port_scanner import validate_target, scan_port, scan_ports
    from module.scanner import escanear_puerto, escanear_rango
    from module.sniffer import capturar_trafico, resumir_captura
    from module.pcap_analyzer import (
        leer_archivo_pcap,
        filtrar_por_protocolo,
        generar_resumen_trafico,
    )


def guardar_reporte(output_path, metadata, resultados, errores=None):
    """Genera el reporte estructurado obligatorio en formato JSON."""
    reporte = {
        "timestamp": datetime.now().isoformat(),
        "metadata": metadata,
        "results": resultados,
        "errors": errores if errores else []
    }
    
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(reporte, f, indent=4, ensure_ascii=False)
        print(f"[✔] Reporte guardado exitosamente en: {output_path}")


def main() -> None:
    """Función principal que controla la CLI de PortLock usando argparse."""
    parser = argparse.ArgumentParser(
        description="PortLock: Herramienta CLI de Ciberseguridad y Análisis de Red.",
        epilog="Ejemplo de uso: python main.py scan-sockets -t 127.0.0.1 -p 80"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcomandos disponibles")

    # --- 1. Subcomando: scan-socket (Puerto único por sockets) ---
    p_socket = subparsers.add_parser("scan-socket", help="Escaneo TCP por Sockets a un puerto único.")
    p_socket.add_argument("-t", "--target", required=True, help="IP o dominio objetivo.")
    p_socket.add_argument("-p", "--port", type=int, required=True, help="Puerto a escanear.")
    p_socket.add_argument("-o", "--output", default="reporte_socket.json", help="Ruta del archivo de salida JSON.")

    # --- 2. Subcomando: scan-sockets-range (Rango de puertos por sockets) ---
    p_srange = subparsers.add_parser("scan-sockets-range", help="Escaneo TCP por Sockets en un rango de puertos.")
    p_srange.add_argument("-t", "--target", required=True, help="IP o dominio objetivo.")
    p_srange.add_argument("--start", type=int, default=1, help="Puerto inicial (por defecto 1).")
    p_srange.add_argument("--end", type=int, default=1024, help="Puerto final (por defecto 1024).")
    p_srange.add_argument("-o", "--output", default="reporte_srange.json", help="Ruta del archivo de salida JSON.")

    # --- 3. Subcomando: scan-syn (Escaneo SYN con Scapy) ---
    p_syn = subparsers.add_parser("scan-syn", help="Escaneo SYN usando Scapy (Requiere privilegios).")
    p_syn.add_argument("-t", "--target", required=True, help="IP o dominio objetivo.")
    p_syn.add_argument("--start", type=int, required=True, help="Puerto inicial.")
    p_syn.add_argument("--end", type=int, required=True, help="Puerto final.")
    p_syn.add_argument("-o", "--output", default="reporte_syn.json", help="Ruta del archivo de salida JSON.")

    # --- 4. Subcomando: sniff (Captura de tráfico en vivo) ---
    p_sniff = subparsers.add_parser("sniff", help="Capturar tráfico de red en vivo (Sniffer).")
    p_sniff.add_argument("-c", "--count", type=int, default=10, help="Cantidad de paquetes a capturar.")
    p_sniff.add_argument("-t", "--time", type=int, default=10, help="Tiempo límite en segundos.")
    p_sniff.add_argument("-f", "--filter", default=None, help="Filtro BPF opcional (ej. 'tcp port 80').")
    p_sniff.add_argument("-o", "--output", default="reporte_sniff.json", help="Ruta del archivo de salida JSON.")

    # --- 5. Subcomando: pcap-summary (Resumen de archivo PCAP) ---
    p_pcap = subparsers.add_parser("pcap-summary", help="Analizar un archivo .pcap y mostrar resumen de IPs.")
    p_pcap.add_argument("-r", "--ruta", required=True, help="Ruta del archivo .pcap a analizar.")

    # --- 6. Subcomando: pcap-filter (Filtrar PCAP por protocolo) ---
    p_pcap_f = subparsers.add_parser("pcap-filter", help="Filtrar paquetes de un .pcap por protocolo.")
    p_pcap_f.add_argument("-r", "--ruta", required=True, help="Ruta del archivo .pcap.")
    p_pcap_f.add_argument("-p", "--protocolo", required=True, help="Protocolo a filtrar (ej. TCP, UDP, IP).")

    args = parser.parse_args()

    try:
        if args.command in ["scan-socket", "scan-sockets-range", "scan-syn"]:
            target_str = preparar_objetivo(args.target)
            ip_obj = validate_target(target_str)
            if not ip_obj:
                print("[!] Error: El objetivo no es una dirección IPv4 válida.", file=sys.stderr)
                sys.exit(1)
            target_ip = str(ip_obj)

        if args.command == "scan-socket":
            print(f"[*] Escaneando {target_ip}:{args.port} con Sockets...")
            abierto = scan_port(target_ip, args.port)
            estado = "ABIERTO" if abierto else "CERRADO"
            print(f"[+] El puerto {args.port} está: {estado}")
            
            resultados = {"target": target_ip, "port": args.port, "status": estado}
            guardar_reporte(args.output, {"mode": "scan-socket"}, resultados)

        elif args.command == "scan-sockets-range":
            print(f"[*] Escaneando rango {args.start}-{args.end} en {target_ip} con Sockets...")
            scan_ports(target_ip, args.start, args.end)
            
            resultados = {"target": target_ip, "start_port": args.start, "end_port": args.end}
            guardar_reporte(args.output, {"mode": "scan-sockets-range"}, resultados)

        elif args.command == "scan-syn":
            print(f"[*] Ejecutando escaneo SYN (Scapy) en {target_ip} ({args.start}-{args.end})...")
            abiertos = escanear_rango(target_ip, args.start, args.end)
            print(f"[+] Puertos abiertos encontrados: {abiertos}")
            
            resultados = {"target": target_ip, "open_ports": abiertos}
            guardar_reporte(args.output, {"mode": "scan-syn"}, resultados)

        elif args.command == "sniff":
            print(f"[*] Capturando tráfico (máx {args.count} paquetes / {args.time}s)...")
            paquetes = capturar_trafico(cantidad=args.count, tiempo=args.time, filtro=args.filter)
            
            if paquetes:
                resumen = resumir_captura(paquetes)
                print(f"\n[+] Captura finalizada. Total de paquetes: {resumen['total']}")
                print(f"[+] Desglose por protocolos: {resumen['protocolos']}")
                guardar_reporte(args.output, {"mode": "sniffer", "filter": args.filter}, resumen)
            else:
                print("[-] No se capturaron paquetes.")
                guardar_reporte(args.output, {"mode": "sniffer"}, {"total": 0, "protocolos": {}})

        elif args.command == "pcap-summary":
            paquetes = leer_archivo_pcap(args.ruta)
            if paquetes:
                generar_resumen_trafico(paquetes)

        elif args.command == "pcap-filter":
            paquetes = leer_archivo_pcap(args.ruta)
            if paquetes:
                proto = args.protocolo.upper()
                filtrados = filtrar_por_protocolo(paquetes, proto)
                if filtrados:
                    generar_resumen_trafico(filtrados)

    except ValueError as e:
        print(f"[!] Error de validación: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"[!] Error de ejecución de red/Scapy: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error inesperado: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
