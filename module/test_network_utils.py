"""Pruebas de network_utils.py."""

import pytest

from module.network_utils import (
    es_ip_valida,
    preparar_objetivo,
    resolver_dominio,
    validar_archivo_salida,
    validar_ip,
    validar_puerto,
    validar_rango_puertos,
)


def test_es_ip_valida():
    """Verifica que solo acepte direcciones IPv4 correctas."""
    assert es_ip_valida("192.168.1.1") is True
    assert es_ip_valida("999.1.1.1") is False
    assert es_ip_valida("hola") is False


def test_resolver_dominio_localhost():
    """Verifica que localhost se resuelva a 127.0.0.1."""
    assert resolver_dominio("localhost") == "127.0.0.1"


def test_resolver_dominio_invalido():
    """Verifica que un dominio inexistente lance ValueError."""
    with pytest.raises(ValueError):
        resolver_dominio("dominio-que-no-existe.invalid")


def test_preparar_objetivo_ip():
    """Verifica que una IP se devuelva limpia, sin espacios."""
    assert preparar_objetivo("  10.0.0.5 ") == "10.0.0.5"


def test_preparar_objetivo_vacio():
    """Verifica que un objetivo vacío lance ValueError."""
    with pytest.raises(ValueError):
        preparar_objetivo("   ")


def test_validar_ip():
    """Verifica IPs y rangos CIDR válidos e inválidos."""
    assert validar_ip("192.168.1.0/24") is True
    assert validar_ip("10.0.0.1") is True
    with pytest.raises(ValueError):
        validar_ip("999.1.1.1")


def test_validar_puerto():
    """Verifica puertos válidos y fuera de rango."""
    assert validar_puerto(80) == 80
    assert validar_puerto("443") == 443
    for invalido in ("0", "70000", "abc"):
        with pytest.raises(ValueError):
            validar_puerto(invalido)


def test_validar_rango_puertos():
    """Verifica puertos únicos, rangos válidos y rangos incorrectos."""
    assert validar_rango_puertos("80") == (80, 80)
    assert validar_rango_puertos("1-1024") == (1, 1024)
    for invalido in ("80-20", "1-2-3", "a-b"):
        with pytest.raises(ValueError):
            validar_rango_puertos(invalido)


def test_validar_archivo_salida(tmp_path):
    """Verifica que acepte un directorio existente y rechace uno falso."""
    assert validar_archivo_salida(str(tmp_path / "reporte.json")) is True
    with pytest.raises(FileNotFoundError):
        validar_archivo_salida(str(tmp_path / "no_existe" / "r.json"))
