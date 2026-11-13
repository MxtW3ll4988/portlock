"""Pruebas de utils.py."""

from datetime import datetime

from module.utils import imprimir_banner, medir_tiempo, timestamp_actual


def test_timestamp_actual_formato_iso():
    """Verifica que la marca de tiempo sea texto en formato ISO 8601."""
    marca = timestamp_actual()
    assert isinstance(marca, str)
    datetime.fromisoformat(marca)


def test_medir_tiempo_devuelve_resultado(capsys):
    """Verifica que el decorador conserve el resultado e imprima el tiempo."""
    @medir_tiempo
    def suma(a, b):
        return a + b

    assert suma(2, 3) == 5
    assert "[TIEMPO] suma" in capsys.readouterr().out


def test_medir_tiempo_conserva_nombre():
    """Verifica que la función decorada conserve su nombre."""
    @medir_tiempo
    def mi_funcion():
        return None

    assert mi_funcion.__name__ == "mi_funcion"


def test_imprimir_banner(capsys):
    """Verifica que el banner muestre el nombre y la versión."""
    imprimir_banner("PortLock", "0.5.0")
    assert "PortLock v0.5.0" in capsys.readouterr().out
