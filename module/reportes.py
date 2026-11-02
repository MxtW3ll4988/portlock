
"""Modulo para generar reportes de PortLock en JSON y CSV."""

import json
import csv
import os
from datetime import datetime

from module.network_utils import validar_archivo_salida


def guardar_reporte(datos, ruta_salida, formato="json"):
    """
    Guarda los resultados de PortLock en JSON o CSV.

    Args:
        datos (dict): Parámetros, resultados y errores encontrados.
        ruta_salida (str): Ruta donde se guardará el reporte.
        formato (str): Formato del reporte: json o csv.

    Raises:
        ValueError: Si el formato no es compatible.
        FileNotFoundError: Si el directorio no existe.
        PermissionError: Si no hay permisos de escritura.
        OSError: Si ocurre un error al guardar.
    """

    formato = formato.lower().strip()

    if formato not in ("json", "csv"):
        raise ValueError("Formato no válido. Utiliza JSON o CSV.")

    if not isinstance(datos, dict):
        raise ValueError("Los datos del reporte deben ser un diccionario.")

    if not ruta_salida or not ruta_salida.strip():
        raise ValueError("La ruta de salida no puede estar vacía.")

    validar_archivo_salida(ruta_salida)

    metadatos = {
        "generado_en": datetime.now().isoformat(),
        "parametros": datos.get("parametros", {}),
        "total_resultados": len(datos.get("resultados", [])),
        "resultados": datos.get("resultados", []),
        "errores": datos.get("errores", [])
    }

    try:
        if formato == "json":
            with open(ruta_salida, "w", encoding="utf-8") as archivo:
                json.dump(
                    metadatos,
                    archivo,
                    indent=4,
                    ensure_ascii=False,
                    default=str
                )

        elif formato == "csv":
            resultados = metadatos["resultados"]

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

                if resultados:
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
                else:
                    escritor.writerow({
                        "generado_en": metadatos["generado_en"],
                        "parametros": json.dumps(
                            metadatos["parametros"],
                            ensure_ascii=False
                        ),
                        "total_resultados": 0,
                        "resultado": "",
                        "errores": json.dumps(
                            metadatos["errores"],
                            ensure_ascii=False
                        )
                    })

        print(f"[OK] Reporte guardado correctamente: {ruta_salida}")
        return True

    except OSError as error:
        print(f"[ERROR] No se pudo guardar el reporte: {error}")
        raise
