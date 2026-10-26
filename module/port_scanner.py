
import ipaddress
import socket
import sys


def validate_target(target: str) -> ipaddress.IPv4Address | None:
    """Valida una dirección IPv4.

    Args:
        target: Dirección IP proporcionada por el usuario.

    Returns:
        Un objeto IPv4Address si la dirección es válida;
        None si el formato es incorrecto o es una dirección IPv6.
    """
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return None

    if not isinstance(ip, ipaddress.IPv4Address):
        return None

    return ip


def scan_port(target: str, port: int) -> bool:
    """Comprueba si un puerto TCP está abierto en el objetivo.

    Args:
        target: Dirección IPv4 del objetivo.
        port: Número del puerto TCP que se comprobará.

    Returns:
        True si la conexión TCP se establece; False en caso contrario.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            return result == 0
    except OSError:
        return False


def scan_ports(
    target: str,
    start_port: int = 1,
    end_port: int = 65535,
) -> list[int]:
    """Escanea un intervalo de puertos TCP.

    Args:
        target: Dirección IPv4 del objetivo.
        start_port: Primer puerto del intervalo, incluido.
        end_port: Último puerto del intervalo, incluido.

    Returns:
        Lista con los números de los puertos abiertos.

    Raises:
        ValueError: Si el intervalo está fuera del rango válido
            o el puerto inicial es mayor que el final.
    """
    if not (1 <= start_port <= end_port <= 65535):
        raise ValueError("El intervalo de puertos no es válido.")

    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(target, port):
            open_ports.append(port)
            print(f"[+] Puerto {port} abierto")

    return open_ports


def main() -> None:
    """Ejecuta el escáner desde la línea de comandos.

    Valida los argumentos, comprueba la dirección IP e inicia
    el escaneo del rango completo de puertos TCP.
    """
    if len(sys.argv) != 2:
        print(f"Uso: python {sys.argv[0]} <direccion_ipv4>")
        sys.exit(1)

    target = validate_target(sys.argv[1])

    if target is None:
        print("[!] El objetivo no es una dirección IPv4 válida.")
        sys.exit(1)

    print(f"[.] Escaneando el objetivo {target}...")

    try:
        scan_ports(str(target))
    except ValueError as error:
        print(f"[!] Error en el escaneo: {error}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(130)

    print("[.] Escaneo finalizado.")


if __name__ == "__main__":
    main()
