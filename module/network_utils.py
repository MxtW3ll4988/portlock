"""network_utils.py — Utilidades de validación y resolución de red

Forma parte de PortLock
Autor: Kimberly Brisseyda Mata Ojeda 
"""

import ipaddress
import socket


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
