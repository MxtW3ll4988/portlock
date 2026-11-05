"""network_utils.py — Utilidades de validación y resolución de red

Forma parte de PortLock
Autor: Kimberly Brisseyda Mata Ojeda.

"""

import ipaddress
import socket
import os


def es_ip_valida(texto):
    """Indica si un texto es una IPv4 válida

    Args:
        texto (str): Cadena a evaluar.

    Returns:
        bool: True si es una IPv4 válida, False si no.
    """
    try:
        ipaddress.IPv4Address(texto)
    except ValueError:
        return False
    return True


def resolver_dominio(dominio):
    """Resuelve un dominio a su dirección IPv4.

    Args:
        dominio (str): Nombre de dominio, por ejemplo "example.com".

    Returns:
        str: Dirección IPv4 del dominio.

    Raises:
        ValueError: Si el dominio no existe o no es válido.
    """
    try:
        return socket.gethostbyname(dominio)
    except (socket.gaierror, UnicodeError) as e:
        raise ValueError(f"'{dominio}' no es un dominio válido.") from e


def preparar_objetivo(entrada):
    """Devuelve una IPv4 lista para el escáner a partir de una IP o dominio.

    Args:
        entrada (str): Dirección dada por el usuario (IP o dominio).

    Returns:
        str: Dirección IPv4 en formato string.

    Raises:
        ValueError: Si la entrada está vacía o no es resoluble.
    """
    entrada = entrada.strip()
    if not entrada:
        raise ValueError("El objetivo de red no puede estar vacío.")
    if es_ip_valida(entrada):
        return entrada
    return resolver_dominio(entrada)


def validar_ip(ip_str):
    """Valida que una cadena sea una IP o un rango CIDR válido.

    Argumentos:
        ip_str (str): IP o rango en formato CIDR, por ejemplo "192.168.1.0/24".

    Devoluciones:
        bool: True si es válido.

    Aumentos:
        ValueError: Si el formato es incorrecto.
    """
    try:
        ipaddress.ip_network(ip_str.strip(), strict=False)
        return True
    except ValueError as e:
        raise ValueError(f"IP/CIDR inválido: '{ip_str}'") from e


def validar_puerto(puerto):
    """Valida que un puerto sea un entero entre 1 y 65535.

    Argumentos:
        puerto (int | str): Número de puerto.

    Devoluciones:
        int: El puerto como entero.

    Aumentos:
        ValueError: Si no es un número o está fuera de rango.
    """
    try:
        numero = int(puerto)
    except ValueError as e:
        raise ValueError(f"Puerto inválido: '{puerto}'") from e
    if numero < 1 or numero > 65535:
        raise ValueError(
            f"Puerto fuera de rango: {numero} (debe ser 1-65535).")
    return numero


def validar_rango_puertos(rango):
    """Valida un puerto o un rango de puertos, por ejemplo "80" o "1-1024".

    Argumentos:
        rango (str): Puerto único o rango "inicio-fin".

    Devoluciones:
        tuple: (puerto_inicio, puerto_fin) como enteros.

     Aumentos:
        ValueError: Si el formato es incorrecto o el inicio es mayor que
            el fin.
    """
    partes = rango.split("-")
    if len(partes) > 2:
        raise ValueError(f"Rango inválido: '{rango}' (usa el formato 1-1024).")

    inicio = validar_puerto(partes[0])
    fin = validar_puerto(partes[-1])
    if inicio > fin:
        raise ValueError(f"Rango inválido: {inicio} es mayor que {fin}.")
    return inicio, fin


def validar_archivo_salida(ruta):
    """Verifica que el directorio de destino exista y se pueda escribir en él.

    Argumentos:
        ruta (str): Ruta del archivo de salida, por ejemplo "reporte.json".

    Devoluciones:
        bool: True si se puede guardar el archivo.

    Aumentos:
        FileNotFoundError: Si el directorio de destino no existe.
        PermissionError: Si no hay permiso de escritura.
    """
    directorio = os.path.dirname(ruta) or "."
    if not os.path.isdir(directorio):
        raise FileNotFoundError(f"El directorio '{directorio}' no existe.")
    if not os.access(directorio, os.W_OK):
        raise PermissionError(
            f"No hay permiso de escritura en '{directorio}'.")
    return True
