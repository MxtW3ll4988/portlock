"""utils.py — Funciones auxiliares compartidas de PortLock

Forma parte de PortLock
Autor: Kimberly Brisseyda Mata Ojeda.

"""

import time
from datetime import datetime
from functools import wraps


def timestamp_actual():
    """Devuelve la fecha y hora actual en formato ISO 8601.

    Devoluciones:
        str: Fecha y hora, por ejemplo "2026-11-02T10:30:00.123456".
    """
    return datetime.now().isoformat()


def medir_tiempo(func):
    """Decorador que imprime cuánto tarda en ejecutarse una función.

    Argumentos:
        func (callable): Función que se quiere medir.

    Devoluciones:
        callable: Función envuelta que devuelve el mismo resultado.

    Ejemplo:
        @medir_tiempo
        def mi_funcion():
            ...
    """
    @wraps(func)
    def envoltura(*args, **kwargs):
        inicio = time.perf_counter()
        resultado = func(*args, **kwargs)
        fin = time.perf_counter()
        print(f"[TIEMPO] {func.__name__}: {fin - inicio:.3f}s")
        return resultado
    return envoltura


def imprimir_banner(nombre, version):
    """Imprime el banner de la librería al iniciar.

    Argumentos:
        nombre (str): Nombre de la librería, por ejemplo "PortLock".
        version (str): Versión de la librería, por ejemplo "0.5.0".
    """
    print(f"\n{'=' * 50}")
    print(f" {nombre} v{version}")
    print(" Herramienta de ciberseguridad defensiva")
    print(f"{'=' * 50}\n")
