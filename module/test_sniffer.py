
import pytest
from scapy.all import IP, TCP, UDP, ICMP, IPv6

from scapy.error import Scapy_Exception
from module import sniffer


def test_analizar_paquete_ipv4_tcp():
    paquete = IP(src="192.168.1.10", dst="192.168.1.20") / TCP()

    resultado = sniffer.analizar_paquete(paquete)

    assert resultado["origen"] == "192.168.1.10"
    assert resultado["destino"] == "192.168.1.20"
    assert "IPv4" in resultado["protocolos"]
    assert "TCP" in resultado["protocolos"]


def test_analizar_paquete_ipv6_udp():
    paquete = IPv6(
        src="2001:db8::1",
        dst="2001:db8::2"
    ) / UDP()

    resultado = sniffer.analizar_paquete(paquete)

    assert resultado["origen"] == "2001:db8::1"
    assert resultado["destino"] == "2001:db8::2"
    assert "IPv6" in resultado["protocolos"]
    assert "UDP" in resultado["protocolos"]


def test_resumir_captura():
    paquetes = [
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(),
        IP(src="192.168.1.5", dst="192.168.1.6") / UDP(),
        IP(src="192.168.1.7", dst="192.168.1.8") / ICMP()
    ]

    resultado = sniffer.resumir_captura(paquetes)

    assert resultado["total"] == 4
    assert resultado["protocolos"]["IPv4"] == 4
    assert resultado["protocolos"]["TCP"] == 2
    assert resultado["protocolos"]["UDP"] == 1
    assert resultado["protocolos"]["ICMP"] == 1


def test_capturar_trafico_simulado(monkeypatch):
    paquetes = [
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
    ]

    def sniff_simulado(**kwargs):
        assert kwargs["count"] == 5
        assert kwargs["timeout"] == 3
        assert kwargs["store"] is True
        return paquetes

    monkeypatch.setattr(sniffer, "sniff", sniff_simulado)

    resultado = sniffer.capturar_trafico(
        cantidad=5,
        tiempo=3
    )

    assert len(resultado) == 1
    assert resultado[0].haslayer(TCP)


def test_capturar_trafico_rechaza_cantidad_invalida():
    with pytest.raises(ValueError):
        sniffer.capturar_trafico(cantidad=0)


def test_capturar_trafico_maneja_error(monkeypatch):
    def sniff_error(**kwargs):
        raise Scapy_Exception("Error simulado")

    monkeypatch.setattr(sniffer, "sniff", sniff_error)

    with pytest.raises(RuntimeError, match="No se pudo capturar"):
        sniffer.capturar_trafico()
