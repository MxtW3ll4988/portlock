
import json
import csv

from module.reportes import guardar_reporte


def datos_prueba():
    return {
        "parametros": {
            "objetivo": "127.0.0.1",
            "puerto": 80
        },
        "resultados": [
            {
                "puerto": 80,
                "estado": "abierto"
            },
            {
                "puerto": 443,
                "estado": "cerrado"
            }
        ],
        "errores": []
    }


def test_guardar_reporte_json(tmp_path):
    ruta = tmp_path / "reporte.json"

    resultado = guardar_reporte(
        datos_prueba(),
        str(ruta),
        "json"
    )

    assert resultado is True
    assert ruta.exists()

    contenido = json.loads(ruta.read_text(encoding="utf-8"))

    assert contenido["total_resultados"] == 2
    assert contenido["parametros"]["objetivo"] == "127.0.0.1"


def test_guardar_reporte_csv(tmp_path):
    ruta = tmp_path / "reporte.csv"

    resultado = guardar_reporte(
        datos_prueba(),
        str(ruta),
        "csv"
    )

    assert resultado is True
    assert ruta.exists()

    with open(ruta, "r", encoding="utf-8") as archivo:
        lector = csv.DictReader(archivo)
        filas = list(lector)

    assert len(filas) == 2
    assert filas[0]["resultado"]


def test_guardar_reporte_txt(tmp_path):
    ruta = tmp_path / "reporte.txt"

    resultado = guardar_reporte(
        datos_prueba(),
        str(ruta),
        "txt"
    )

    assert resultado is True
    assert ruta.exists()

    contenido = ruta.read_text(encoding="utf-8")

    assert "REPORTE DE PORTLOCK" in contenido
    assert "Total de resultados: 2" in contenido
    assert "No se registraron errores." in contenido
