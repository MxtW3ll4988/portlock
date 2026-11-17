
import pytest

from module import port_scanner


def test_validate_target_ipv4_valida():
    resultado = port_scanner.validate_target("192.168.1.1")

    assert resultado is not None
    assert str(resultado) == "192.168.1.1"


def test_validate_target_rechaza_ipv6_e_invalida():
    assert port_scanner.validate_target("2001:db8::1") is None
    assert port_scanner.validate_target("direccion_invalida") is None


def test_scan_ports_identifica_puertos_abiertos(monkeypatch):
    def scan_simulado(target, port):
        return port in [80, 443]

    monkeypatch.setattr(port_scanner, "scan_port", scan_simulado)

    resultado = port_scanner.scan_ports(
        "127.0.0.1",
        start_port=80,
        end_port=443
    )

    assert resultado == [80, 443]


def test_scan_ports_rechaza_intervalo_invalido():
    with pytest.raises(ValueError):
        port_scanner.scan_ports(
            "127.0.0.1",
            start_port=100,
            end_port=50
        )
