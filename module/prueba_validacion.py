import network_utils as nu


def probar(funcion, valor):
    try:
        print(funcion.__name__, repr(valor), "->", funcion(valor))
    except Exception as e:
        print(funcion.__name__, repr(valor), "-> ERROR:", e)


probar(nu.validar_ip, "192.168.1.0/24")
probar(nu.validar_ip, "999.1.1.1")
probar(nu.validar_puerto, 80)
probar(nu.validar_puerto, "0")
probar(nu.validar_puerto, "abc")
probar(nu.validar_rango_puertos, "1-1024")
probar(nu.validar_rango_puertos, "80-20")
probar(nu.validar_archivo_salida, "reporte.json")
probar(nu.validar_archivo_salida, "carpeta_que_no_existe/reporte.json")
