import os
from interoperabilidad import detectar_os, ejecutar_comando, enumerar_sistema

def test_detectar_os():
    """Verifica que detecte un sistema operativo válido."""
    so = detectar_os()
    assert so in ["Windows", "Linux/macOS", "Desconocido"]

def test_ejecutar_comando():
    """Verifica que la ejecución de un comando básico devuelva texto."""
    salida = ejecutar_comando("echo hola")
    assert "hola" in salida

def test_enumerar_sistema_estructura():
    """Verifica que la función devuelva un diccionario con las llaves clave."""
    resultado = enumerar_sistema()
    assert isinstance(resultado, dict)
    assert "os_detectado" in resultado
    assert "hostname" in resultado
