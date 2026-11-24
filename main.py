"""Menú interactivo CLI para la herramienta PortLock."""

import sys
import argparse
from pathlib import Path
from module.interoperabilidad import enumerar_sistema

from module import (
    preparar_objetivo,
    validar_puerto,
    validar_rango_puertos,
    validate_target,
    scan_port,
    scan_ports,
    escanear_rango,
    capturar_trafico,
    resumir_captura,
    leer_archivo_pcap,
    filtrar_por_protocolo,
    generar_resumen_trafico,
    guardar_reporte,
)

VERDE = "\033[92m"
AMARILLO = "\033[93m"
ROJO = "\033[91m"
AZUL = "\033[94m"
RESET = "\033[0m"
NEGRITA = "\033[1m"


def guardar_resultado(comando_nombre, parametros, resultados, errores=None, formato="json", output=None):
    ruta = output or f"reporte_{comando_nombre}.{formato}"
    datos = {
        "parametros": parametros,
        "resultados": resultados,
        "errores": errores or [],
    }

    try:
        guardar_reporte(datos, ruta, formato)
        print(f"{VERDE}[✔]{RESET} Reporte guardado en: {NEGRITA}{ruta}{RESET}")
    except (ValueError, OSError) as error:
        print(f"{ROJO}[✖] No se pudo generar el reporte: {error}{RESET}", file=sys.stderr)


def validar_objetivo(entrada):
    objetivo = preparar_objetivo(entrada)
    ip_objetivo = validate_target(objetivo)
    if ip_objetivo is None:
        raise ValueError("El objetivo debe ser una dirección IPv4 válida.")
    return str(ip_objetivo)


def menu_scan():
    print(f"\n{NEGRITA}=== 1. Escaneo de un Puerto TCP (Sockets) ==={RESET}")
    try:
        target_in = input("Introduce la IP o dominio objetivo: ").strip()
        objetivo = validar_objetivo(target_in)
        port_in = int(input("Introduce el puerto TCP (1-65535): ").strip())
        puerto = validar_puerto(port_in)
    except ValueError as e:
        print(f"{ROJO}[!] Entrada inválida: {e}{RESET}")
        return

    print(f"[*] Analizando puerto {puerto} en {objetivo}...")
    abierto = scan_port(objetivo, puerto)
    estado = "ABIERTO" if abierto else "CERRADO"
    color_estado = VERDE if abierto else ROJO

    print(f"\n{NEGRITA}[✦] Resultado:{RESET} {objetivo}:{puerto} -> {color_estado}{NEGRITA}{estado}{RESET}\n")

    guardar_opcion = input("¿Deseas guardar el reporte? (s/n): ").strip().lower()
    if guardar_opcion == 's':
        fmt = input("Formato [json/csv/txt] (default json): ").strip() or "json"
        guardar_resultado("scan", {"objetivo": objetivo, "puerto": puerto}, [{"puerto": puerto, "estado": estado}], formato=fmt)


def menu_scan_range():
    print(f"\n{NEGRITA}=== 2. Escaneo de Rango de Puertos (Sockets) ==={RESET}")
    try:
        target_in = input("Introduce la IP o dominio objetivo: ").strip()
        objetivo = validar_objetivo(target_in)
        inicio = int(input("Puerto inicial: ").strip())
        fin = int(input("Puerto final: ").strip())
        val_inicio, val_fin = validar_rango_puertos(f"{inicio}-{fin}")
    except ValueError as e:
        print(f"{ROJO}[!] Entrada inválida: {e}{RESET}")
        return

    print(f"[*] Escaneando rango ({val_inicio}-{val_fin}) en {objetivo}...")
    abiertos = scan_ports(objetivo, val_inicio, val_fin)

    print(f"\n{NEGRITA}[✦] Puertos abiertos encontrados:{RESET} {VERDE}{abiertos}{RESET}\n")

    if input("¿Deseas guardar el reporte? (s/n): ").strip().lower() == 's':
        fmt = input("Formato [json/csv/txt] (default json): ").strip() or "json"
        guardar_resultado("scan_range", {"objetivo": objetivo, "inicio": val_inicio, "fin": val_fin}, [{"puerto": p, "estado": "ABIERTO"} for p in abiertos], formato=fmt)


def menu_syn():
    print(f"\n{NEGRITA}=== 3. Escaneo SYN Sigiloso (Scapy) ==={RESET}")
    try:
        target_in = input("Introduce la IP o dominio objetivo: ").strip()
        objetivo = validar_objetivo(target_in)
        inicio = int(input("Puerto inicial: ").strip())
        fin = int(input("Puerto final: ").strip())
        val_inicio, val_fin = validar_rango_puertos(f"{inicio}-{fin}")
    except ValueError as e:
        print(f"{ROJO}[!] Entrada inválida: {e}{RESET}")
        return

    print(f"[*] Ejecutando escaneo SYN en {objetivo}...")
    abiertos = escanear_rango(objetivo, val_inicio, val_fin)

    print(f"\n{NEGRITA}[✦] Puertos abiertos por SYN:{RESET} {VERDE}{abiertos}{RESET}\n")

    if input("¿Deseas guardar el reporte? (s/n): ").strip().lower() == 's':
        fmt = input("Formato [json/csv/txt] (default json): ").strip() or "json"
        guardar_resultado("syn", {"objetivo": objetivo, "inicio": val_inicio, "fin": val_fin}, [{"puerto": p, "estado": "ABIERTO"} for p in abiertos], formato=fmt)


def menu_sniffer():
    print(f"\n{NEGRITA}=== 4. Sniffer de Tráfico de Red ==={RESET}")
    try:
        count = int(input("Cantidad máxima de paquetes (default 10): ").strip() or "10")
        timeout = int(input("Tiempo límite en segundos (default 10): ").strip() or "10")
        filtro = input("Filtro BPF opcional (ej. 'tcp port 80' o dejar en blanco): ").strip() or None
    except ValueError:
        print(f"{ROJO}[!] Valores numéricos inválidos.{RESET}")
        return

    print(f"[*] Capturando tráfico por {timeout}s...")
    try:
        paquetes = capturar_trafico(cantidad=count, tiempo=timeout, filtro=filtro)
    except Exception as e:
        print(f"{ROJO}[!] Error al capturar tráfico: {e}{RESET}")
        return

    if not paquetes:
        print(f"{AMARILLO}[-] No se capturaron paquetes.{RESET}\n")
        resumen = {"total": 0, "protocolos": {}}
        resultados = []
    else:
        resumen = resumir_captura(paquetes)
        print(f"\n{NEGRITA}[✦] Resumen de Captura:{RESET}")
        print(f"    Total paquetes : {AZUL}{resumen['total']}{RESET}")
        print(f"    Protocolos     : {resumen['protocolos']}\n")
        resultados = [resumen]

    if input("¿Deseas guardar el reporte? (s/n): ").strip().lower() == 's':
        fmt = input("Formato [json/csv/txt] (default json): ").strip() or "json"
        guardar_resultado("sniffer", {"count": count, "timeout": timeout}, resultados, formato=fmt)


def menu_pcap():
    print(f"\n{NEGRITA}=== 5. Analizar Archivo PCAP ==={RESET}")
    ruta_pcap = input("Introduce la ruta del archivo .pcap: ").strip()

    print(f"[*] Leyendo archivo {ruta_pcap}...")
    paquetes = leer_archivo_pcap(ruta_pcap)
    if not paquetes:
        print(f"{ROJO}[-] No se pudo leer el archivo PCAP o está vacío.{RESET}\n")
        return

    print(f"\n{NEGRITA}[✦] Archivo leído correctamente.{RESET} Total paquetes: {AZUL}{len(paquetes)}{RESET}\n")
    generar_resumen_trafico(paquetes)

    resultados = [{"paquete": i + 1, "resumen": p.summary()} for i, p in enumerate(paquetes[:5])]
    if input("¿Deseas guardar el reporte? (s/n): ").strip().lower() == 's':
        fmt = input("Formato [json/csv/txt] (default json): ").strip() or "json"
        guardar_resultado("pcap", {"archivo": ruta_pcap, "total": len(paquetes)}, resultados, formato=fmt)


def menu_pcap_filter():
    print(f"\n{NEGRITA}=== 6. Filtrar PCAP por Protocolo ==={RESET}")
    ruta_pcap = input("Introduce la ruta del archivo .pcap: ").strip()
    protocolo = input("Introduce el protocolo (ej. TCP, UDP, ICMP): ").strip().upper()

    print(f"[*] Filtrando paquetes {protocolo}...")
    paquetes = leer_archivo_pcap(ruta_pcap)
    if not paquetes:
        print(f"{ROJO}[-] No se pudo leer el archivo PCAP.{RESET}\n")
        return

    filtrados = filtrar_por_protocolo(paquetes, protocolo)
    print(f"\n{NEGRITA}[✦] Paquetes encontrados para {protocolo}: {VERDE}{len(filtrados)}{RESET}\n")
    if filtrados:
        generar_resumen_trafico(filtrados)

    resultados = [{"paquete": i + 1, "protocolo": protocolo, "resumen": p.summary()} for i, p in enumerate(filtrados[:5])]
    if input("¿Deseas guardar el reporte? (s/n): ").strip().lower() == 's':
        fmt = input("Formato [json/csv/txt] (default json): ").strip() or "json"
        guardar_resultado("pcap_filter", {"archivo": ruta_pcap, "protocolo": protocolo}, resultados, formato=fmt)


def menu_enumerar():
    print(f"\n{NEGRITA}=== 7. Enumeración Defensiva (Interoperabilidad) ==={RESET}")
    ruta_salida = input("Ruta del archivo de salida [default: enum.json]: ").strip() or "enum.json"

    ruta = Path(ruta_salida)
    ruta.parent.mkdir(parents=True, exist_ok=True)

    print("[*] Detectando sistema operativo y ejecutando script nativo...")
    resultado = enumerar_sistema(str(ruta))

    if resultado["success"]:
        print(f"\n{VERDE}[✔] Enumeración completada exitosamente.{RESET}")
        print(f"{VERDE}[✔] Reporte guardado en: {NEGRITA}{ruta}{RESET}\n")
    else:
        print(f"\n{ROJO}[!] La enumeración presentó errores:{RESET}")
        print(resultado["errors"])


def main():
    while True:
        print(f"\n{AZUL}{NEGRITA}============================================={RESET}")
        print(f"{AZUL}{NEGRITA}            PORTLOCK - MENÚ PRINCIPAL         {RESET}")
        print(f"{AZUL}{NEGRITA}============================================={RESET}")
        print(f" {AZUL}{NEGRITA}1.{RESET} Escaneo de un Puerto TCP (Sockets)")
        print(f" {AZUL}{NEGRITA}2.{RESET} Escaneo de Rango de Puertos (Sockets)")
        print(f" {AZUL}{NEGRITA}3.{RESET} Escaneo SYN Sigiloso (Scapy)")
        print(f" {AZUL}{NEGRITA}4.{RESET} Sniffer de Tráfico de Red")
        print(f" {AZUL}{NEGRITA}5.{RESET} Analizar Archivo PCAP")
        print(f" {AZUL}{NEGRITA}6.{RESET} Filtrar PCAP por Protocolo")
        print(f" {AZUL}{NEGRITA}7.{RESET} Interoperabilidad")
        print(f" {AZUL}{NEGRITA}8.{RESET} Salir del Menú")
        print(f"{AZUL}---------------------------------------------{RESET}")

        opcion = input(f"{NEGRITA}Elige una opción (1-8): {RESET}").strip()

        if opcion == "1":
            menu_scan()
        elif opcion == "2":
            menu_scan_range()
        elif opcion == "3":
            menu_syn()
        elif opcion == "4":
            menu_sniffer()
        elif opcion == "5":
            menu_pcap()
        elif opcion == "6":
            menu_pcap_filter()
        elif opcion == "7":
            menu_enumerar()
        elif opcion == "8":
            print(f"\n{VERDE}[✔] Saliendo de PortLock. ¡Hasta luego!{RESET}\n")
            break
        else:
            print(f"\n{ROJO}[!] Opción no válida. Por favor, elige un número del 1 al 8.{RESET}")

        input(f"\n{AMARILLO}Presiona Enter para continuar...{RESET}")


def ejecutar_cli():
    parser = argparse.ArgumentParser(
        description="PortLock - Herramienta de seguridad informática"
    )
    subparsers = parser.add_subparsers(dest="comando")
    parser_enum = subparsers.add_parser(
        "enumerar",
        help="Realiza una enumeración defensiva del sistema"
    )
    parser_enum.add_argument(
        "--output",
        default="enum.json",
        help="Ruta donde se guardará el reporte"
    )

    args = parser.parse_args()

    if args.comando == "enumerar":
        ruta = Path(args.output)
        ruta.parent.mkdir(parents=True, exist_ok=True)
        resultado = enumerar_sistema(str(ruta))
        if resultado["success"]:
            print(f"{VERDE}[✔] Enumeración completada.{RESET}")
            print(f"{VERDE}[✔] Reporte guardado en: {ruta}{RESET}")
        else:
            print(f"{ROJO}[!] La enumeración presentó errores.{RESET}")
            print(resultado["errors"])
            sys.exit(1)


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            ejecutar_cli()
        else:
            main()

    except KeyboardInterrupt:
        print(f"\n\n{ROJO}[!] Programa interrumpido por el usuario.{RESET}")
        sys.exit(0)
