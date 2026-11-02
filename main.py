"""Punto de entrada principal (CLI) para la herramienta de ciberseguridad PortLock."""

import sys
import argparse
from module.reportes import guardar_reporte

# Importación de módulos del paquete PortLock
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
    # Ruta alternativa por si se ejecuta desde la raíz del proyecto
    from portlock.module.network_utils import preparar_objetivo
    from portlock.module.port_scanner import validate_target, scan_port, scan_ports
    from module.scanner import escanear_puerto, escanear_rango
    from module.sniffer import capturar_trafico, resumir_captura
    from module.pcap_analyzer import (
        leer_archivo_pcap,
        filtrar_por_protocolo,
        generar_resumen_trafico,
    )

def generar_reporte_portlock(parametros, resultados, errores=None):
    """Solicita el formato y guarda el reporte de PortLock."""

    datos = {
        "parametros": parametros,
        "resultados": resultados,
        "errores": errores or []
    }

    formato = input("Formato del reporte (json/csv): ").strip().lower()

    if formato not in ("json", "csv"):
        print("[!] Formato no válido.")
        return

    ruta = input(
        f"Nombre del archivo de salida (ej. reporte.{formato}): "
    ).strip()

    try:
        guardar_reporte(datos, ruta, formato)
    except (ValueError, OSError) as error:
        print(f"[!] Error al generar el reporte: {error}")

def mostrar_menu() -> None:
    """Muestra el menú principal de opciones de PortLock."""
    print("\n" + "=" * 50)
    print("         PORTLOCK - Herramienta de Ciberseguridad")
    print("=" * 50)
    print("1. Escaneo TCP por Sockets (Puerto único)")
    print("2. Escaneo TCP por Sockets (Rango completo)")
    print("3. Escaneo SYN con Scapy (Requiere privilegios)")
    print("4. Capturar tráfico de red (Sniffer en vivo)")
    print("5. Analizar archivo PCAP (Resumen IP)")
    print("6. Filtrar paquetes PCAP por protocolo")
    print("7. Salir")
    print("-" * 50)


def main() -> None:
    """Función principal que controla la ejecución de la interfaz de comandos."""
    while True:
        mostrar_menu()
        opcion = input("\nSelecciona una opción (1-7): ").strip()

        if opcion == "1":
            entrada = input("Ingresa la IP o dominio objetivo: ").strip()
            try:
                target_str = preparar_objetivo(entrada)
                ip_obj = validate_target(target_str)
                if ip_obj:
                    port = int(input("Ingresa el puerto a escanear: "))
                    print(f"[*] Escaneando {ip_obj}:{port} con Sockets...")

                    abierto = scan_port(str(ip_obj), port)

                    estado = "ABIERTO" if abierto else "CERRADO"

                    print(f"[+] El puerto {port} está: {estado}")

                    generar_reporte_portlock(
                    parametros={
                     "objetivo": str(ip_obj),
                     "puerto": port
                     },
                    resultados=[
                    {
                       "puerto": port,
                      "estado": estado
                       }
                     ],
                     errores=[]
                    )
                else:
                    print("[!] El objetivo no es una dirección IPv4 válida.")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif opcion == "2":
            entrada = input("Ingresa la IP o dominio objetivo: ").strip()
            try:
                target_str = preparar_objetivo(entrada)
                ip_obj = validate_target(target_str)
                if ip_obj:
                    inicio = int(input("Puerto inicial (por defecto 1): ") or 1)
                    fin = int(input("Puerto final (por defecto 1024): ") or 1024)
                    print(f"[*] Escaneando rango {inicio}-{fin} en {ip_obj}...")

                    abiertos = scan_ports(str(ip_obj), inicio, fin)

                    print(f"[+] Puertos abiertos encontrados: {abiertos}")

                    generar_reporte_portlock(
                    parametros={
                            "objetivo": str(ip_obj),
                            "puerto_inicial": inicio,
                            "puerto_final": fin
                            },
                    resultados=[
                    {
                        "puerto": puerto,
                        "estado": "ABIERTO"
                    }
                   for puerto in abiertos
            ],
            errores=[]
            )
                else:
                    print("[!] El objetivo no es una dirección IPv4 válida.")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif opcion == "3":
            entrada = input("Ingresa la IP o dominio objetivo: ").strip()
            try:
                target_str = preparar_objetivo(entrada)
                ip_obj = validate_target(target_str)
                if ip_obj:
                    inicio = int(input("Puerto inicial (ej. 1): "))
                    fin = int(input("Puerto final (ej. 1024): "))
                    print(f"[*] Ejecutando escaneo SYN (Scapy) en {ip_obj}...")

                    abiertos = escanear_rango(str(ip_obj), inicio, fin)

                    print(f"[+] Puertos abiertos encontrados: {abiertos}")

                    generar_reporte_portlock(
                    parametros={
                    "objetivo": str(ip_obj),
                    "tipo_escaneo": "SYN con Scapy",
                    "puerto_inicial": inicio,
                    "puerto_final": fin
                    },
                    resultados=[
                    {
                    "puerto": puerto,
                    "estado": "ABIERTO"
                    }
                    for puerto in abiertos
                    ],
                        errores=[]
                        )
                else:
                    print("[!] El objetivo no es una dirección IPv4 válida.")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif opcion == "4":
            print("[*] Configuración del Sniffer de Red:")
            try:
                cantidad = int(input("Cantidad de paquetes a capturar (ej. 10): ") or 10)
                tiempo = int(input("Tiempo límite en segundos (ej. 10): ") or 10)
                filtro = input("Filtro BPF opcional (ej. 'tcp port 80' o dejar vacío): ").strip()
                filtro = filtro if filtro else None

                print(f"[*] Capturando tráfico (máx {cantidad} paquetes / {tiempo}s)...")
                paquetes = capturar_trafico(cantidad=cantidad, tiempo=tiempo, filtro=filtro)

                if paquetes:
                    resumen = resumir_captura(paquetes)

                    print(f"\n[+] Captura finalizada. Total de paquetes: {resumen['total']}")
                    print(f"[+] Desglose por protocolos: {resumen['protocolos']}")

                    generar_reporte_portlock(
                    parametros={
                        "tipo": "Captura de tráfico de red",
                        "cantidad_maxima": cantidad,
                        "tiempo_limite": tiempo,
                        "filtro": filtro
                    },
                       resultados=[resumen],
                        errores=[]
                    )
                else:
                    print("[-] No se capturaron paquetes.")
            except (ValueError, RuntimeError) as e:
                print(f"[!] Error en el sniffer: {e}")

        elif opcion == "5":
            ruta = input("Ingresa la ruta del archivo .pcap a analizar: ").strip()
            paquetes = leer_archivo_pcap(ruta)

            if paquetes:
                generar_resumen_trafico(paquetes)

                resultados = []

                for i, paquete in enumerate(paquetes[:5]):
                    resultado = {
                        "paquete": i + 1,
                        "resumen": paquete.summary()
                    }
                    resultados.append(resultado)

                generar_reporte_portlock(
                    parametros={
                        "tipo": "Análisis de archivo PCAP",
                        "archivo": ruta,
                        "total_paquetes": len(paquetes)
                    },
                    resultados=resultados,
            errores=[]
                )

        elif opcion == "6":
            ruta = input("Ingresa la ruta del archivo .pcap: ").strip()
            paquetes = leer_archivo_pcap(ruta)

            if paquetes:
                protocolo = input(
                    "Ingresa el protocolo a filtrar (ej. TCP, UDP, IP): "
                ).strip().upper()

                filtrados = filtrar_por_protocolo(paquetes, protocolo)

                if filtrados:
                    generar_resumen_trafico(filtrados)

                    resultados = []

                    for i, paquete in enumerate(filtrados[:5]):
                        resultados.append({
                            "paquete": i + 1,
                            "protocolo": protocolo,
                            "resumen": paquete.summary()
                        })

                    generar_reporte_portlock(
                        parametros={
                            "tipo": "Filtrado de paquetes PCAP",
                            "archivo": ruta,
                            "protocolo": protocolo,
                            "total_paquetes_filtrados": len(filtrados)
                                },
                                resultados=resultados,
                        errores=[]
                    )
                else:
                    print("[-] No se encontraron paquetes para ese protocolo.")

        elif opcion == "7":
            print("\nSaliendo de PortLock. ¡Hasta luego!")
            sys.exit(0)
        else:
            print("[!] Opción no válida. Por favor, selecciona una opción entre 1 y 7.")


if __name__ == "__main__":
    main()
