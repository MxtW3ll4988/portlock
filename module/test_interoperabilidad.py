"""Pruebas de interoperabilidad.py."""

import json

import pytest

from module.interoperabilidad import (
    SECTIONS,
    detect_os,
    enumerar_sistema,
    get_command,
    parse_output,
)


def test_detect_os():
    """Verifica que detecte un sistema operativo válido."""
    assert detect_os() in ("Windows", "Linux", "Darwin")


def test_get_command_por_sistema():
    """Verifica que cada sistema use su propio shell."""
    assert get_command("Windows")[0] == "powershell"
    assert get_command("Linux")[0] == "bash"
    assert get_command("Darwin")[0] == "bash"


def test_get_command_sistema_no_compatible():
    """Verifica que un sistema desconocido lance RuntimeError."""
    with pytest.raises(RuntimeError):
        get_command("Plan9")


def test_parse_output_estructura():
    """Verifica que la salida de un script se separe por secciones."""
    salida = (
        "### hostname\nmi-pc\n"
        "### current_user\nkim\n"
        "### listening_ports\n0.0.0.0:80 pid=4\n"
    )
    datos = parse_output(salida)
    assert datos["hostname"] == "mi-pc"
    assert datos["current_user"] == "kim"
    assert datos["listening_ports"] == ["0.0.0.0:80 pid=4"]
    assert set(datos) == set(SECTIONS)


def test_enumerar_sistema_estructura():
    """Verifica que devuelva un diccionario con las llaves esperadas."""
    resultado = enumerar_sistema()
    assert isinstance(resultado, dict)
    for llave in ("timestamp", "os", "return_code", "success", "errors",
                  "data"):
        assert llave in resultado
    assert set(resultado["data"]) == set(SECTIONS)


def test_enumerar_sistema_guarda_json(tmp_path):
    """Verifica que el reporte se guarde como JSON válido."""
    ruta = tmp_path / "enum.json"
    enumerar_sistema(str(ruta))
    contenido = json.loads(ruta.read_text(encoding="utf-8"))
    assert "os" in contenido
    assert "data" in contenido
