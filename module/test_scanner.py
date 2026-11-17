
from scapy.all import IP, TCP

from module import scanner


def test_validar_puerto():
    assert scanner.validar_puerto(80) is True
    assert scanner.validar_puerto(443) is True
    assert scanner.validar_puerto(0) is False
    assert scanner.validar_puerto(65536) is False


def test_escanear_puerto_abierto(monkeypatch):
    respuesta = IP(dst="127.0.0.1") / TCP(flags="SA")

    monkeypatch.setattr(
        scanner,
        "sr1",
        lambda *args, **kwargs: respuesta
    )

    resultado = scanner.escanear_puerto("127.0.0.1", 80)

    assert resultado is True


def test_escanear_puerto_sin_respuesta(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "sr1",
        lambda *args, **kwargs: None
    )

    resultado = scanner.escanear_puerto("127.0.0.1", 80)

    assert resultado is False


def test_escanear_rango(monkeypatch):
    def escaneo_simulado(ip, puerto):
        return puerto in [80, 443]

    monkeypatch.setattr(
        scanner,
        "escanear_puerto",
        escaneo_simulado
    )

    resultado = scanner.escanear_rango(
        "127.0.0.1",
        80,
        443
    )

    assert resultado == [80, 443]
