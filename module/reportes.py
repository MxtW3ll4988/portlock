
"""Modulo para generar reportes de PortLock en JSON, CSV y TXT."""

import json
import csv

from .network_utils import validar_archivo_salida
from .utils import timestamp_actual, medir_tiempo


def _guardar_json(metadatos, ruta_salida):
    """Guarda los resultados en formato JSON."""
    with open(ruta_salida, "w", encoding="utf-8") as archivo:
        json.dump(
            metadatos,
            archivo,
            indent=4,
            ensure_ascii=False,
            default=str
        )


def _guardar_csv(metadatos, ruta_salida):
    """Guarda los resultados en formato CSV."""
    campos = [
        "generado_en",
        "parametros",
        "total_resultados",
        "resultado",
        "errores"
    ]

    with open(
        ruta_salida,
        "w",
        newline="",
        encoding="utf-8"
    ) as archivo:

        escritor = csv.DictWriter(
            archivo,
            fieldnames=campos
        )

        escritor.writeheader()

        resultados = metadatos["resultados"]

        if not resultados:
            resultados = [{}]

        for resultado in resultados:
            escritor.writerow({
                "generado_en": metadatos["generado_en"],
                "parametros": json.dumps(
                    metadatos["parametros"],
                    ensure_ascii=False
                ),
                "total_resultados": metadatos["total_resultados"],
                "resultado": json.dumps(
                    resultado,
                    ensure_ascii=False,
                    default=str
                ),
                "errores": json.dumps(
                    metadatos["errores"],
                    ensure_ascii=False
                )
            })


def _guardar_txt(metadatos, ruta_salida):
    """Guarda los resultados en formato de texto TXT."""
    with open(ruta_salida, "w", encoding="utf-8") as archivo:
        archivo.write("=" * 50 + "\n")
        archivo.write("REPORTE DE PORTLOCK\n")
        archivo.write("=" * 50 + "\n\n")

        archivo.write(
            f"Fecha de generación: {metadatos['generado_en']}\n"
        )

        archivo.write(
            f"Total de resultados: {metadatos['total_resultados']}\n\n"
        )

        archivo.write("--- PARAMETROS ---\n")
        archivo.write(
            json.dumps(
                metadatos["parametros"],
                indent=4,
                ensure_ascii=False,
                default=str
            )
        )

        archivo.write("\n\n--- RESULTADOS ---\n")

        if metadatos["resultados"]:
            for numero, resultado in enumerate(
                metadatos["resultados"], start=1
            ):
                archivo.write(f"\nResultado {numero}:\n")
                archivo.write(
                    json.dumps(
                        resultado,
                        indent=4,
                        ensure_ascii=False,
                        default=str
                    )
                )
                archivo.write("\n")
        else:
            archivo.write("No se encontraron resultados.\n")

        archivo.write("\n--- ERRORES ---\n")

        if metadatos["errores"]:
            for error in metadatos["errores"]:
                archivo.write(f"- {error}\n")
        else:
            archivo.write("No se registraron errores.\n")

        archivo.write("\n" + "=" * 50 + "\n")
        archivo.write("Fin del reporte PortLock\n")


@medir_tiempo
def guardar_reporte(datos, ruta_salida, formato="json"):
    """
    Guarda los resultados de PortLock en JSON, CSV o TXT.

    Args:
        datos (dict): Parametros, resultados y errores encontrados.
        ruta_salida (str): Ruta donde se guardara el reporte.
        formato (str): Formato del reporte: json, csv o txt.

    Returns:
        bool: True si el reporte se guardo correctamente.

    Raises:
        ValueError: Si los datos o el formato no son validos.
        FileNotFoundError: Si el directorio no existe.
        PermissionError: Si no hay permisos de escritura.
        OSError: Si ocurre un error al guardar.
    """

    if not isinstance(formato, str):
        raise ValueError("El formato debe ser un texto.")

    formato = formato.lower().strip()

    if formato not in ("json", "csv", "txt"):
        raise ValueError(
            "Formato no valido. Utiliza JSON, CSV o TXT."
        )

    if not isinstance(datos, dict):
        raise ValueError(
            "Los datos del reporte deben ser un diccionario."
        )

    if not isinstance(ruta_salida, str) or not ruta_salida.strip():
        raise ValueError("La ruta de salida no puede estar vacia.")

    resultados = datos.get("resultados", [])
    errores = datos.get("errores", [])

    if not isinstance(resultados, list):
        raise ValueError("Los resultados deben estar en una lista.")

    if not isinstance(errores, list):
        raise ValueError("Los errores deben estar en una lista.")

    validar_archivo_salida(ruta_salida)

    metadatos = {
        "generado_en": timestamp_actual(),
        "parametros": datos.get("parametros", {}),
        "total_resultados": len(resultados),
        "resultados": resultados,
        "errores": errores
    }

    try:
        if formato == "json":
            _guardar_json(metadatos, ruta_salida)

        elif formato == "csv":
            _guardar_csv(metadatos, ruta_salida)

        elif formato == "txt":
            _guardar_txt(metadatos, ruta_salida)

        print(
            f"[OK] Reporte {formato.upper()} guardado: {ruta_salida}"
        )

        return True

    except OSError as error:
        print(f"[ERROR] No se pudo guardar el reporte: {error}")
        raise
