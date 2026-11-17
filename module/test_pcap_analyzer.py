
import pytest
from scapy.all import IP, TCP, UDP, wrpcap
from module import pcap_analyzer


def test_leer_archivo_pcap(tmp_path):
    ruta = tmp_path / "prueba.pcap"

    paquetes = [
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(),
        IP(src="192.168.1.3", dst="192.168.1.4") / UDP()
    ]

    wrpcap(str(ruta), paquetes)

    resultado = pcap_analyzer.leer_archivo_pcap(str(ruta))

    assert len(resultado) == 2


def test_leer_archivo_pcap_inexistente(tmp_path):
    ruta = tmp_path / "inexistente.pcap"

    resultado = pcap_analyzer.leer_archivo_pcap(str(ruta))

    assert resultado == []


def test_filtrar_por_protocolo_tcp():
    paquetes = [
        IP() / TCP(),
        IP() / UDP(),
        IP() / TCP()
    ]

    resultado = pcap_analyzer.filtrar_por_protocolo(
        paquetes, "TCP"
    )

    assert len(resultado) == 2
    assert all(pkt.haslayer(TCP) for pkt in resultado)


def test_filtrar_por_protocolo_udp():
    paquetes = [
        IP() / TCP(),
        IP() / UDP(),
        IP() / UDP()
    ]

    resultado = pcap_analyzer.filtrar_por_protocolo(
        paquetes, "UDP"
    )

    assert len(resultado) == 2


def test_generar_resumen_trafico(capsys):
    paquetes = [
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP()
    ]

    pcap_analyzer.generar_resumen_trafico(paquetes)

    salida = capsys.readouterr().out

    assert "192.168.1.1" in salida
    assert "192.168.1.2" in salida


def test_generar_resumen_sin_paquetes(capsys):
    pcap_analyzer.generar_resumen_trafico([])

    salida = capsys.readouterr().out

    assert "No hay paquetes disponibles" in salida
