 # PCproject
**Docente:** Perla Marlene Viera Gonzalez
## Datos personales

- **Nombre:** Angel Emmanuel Garcia Ibarra
- **Matricula:** 2117906
- **Carrera:** LSTI
- **Semestre:** 3
- **Nombre:** Gretel Denisse Manzo Medina
- **Matrucula:** 2149592
- **Carrera:** LSTI
- **Semestre:** 3
- **Nombre:** Angel Eduardo Guevara Cruz
- **Matricula:** 2167129
- **Carrera:** LSTI
- **Semestre:** 3
- **Nombre:** Kimberly Brisseyda Mata Ojeda
- **Matricula:** 2203372
- **Carrera:** LSTI
- **Semestre:** 3
- **Nombre:** Andrea Reyes Silva
- **Matricula:** 2189711
- **Carrera:** LSTI
- **Semestre:** 3
- **Nombre:** Oswaldo Nabat Aranda Correa
- **Matricula:** 2205477
- **Carrera:** LSTI
- **Semestre:** 3
# Nombre de la librería: PortLock
PortLock es una herramienta modular en python para el reconocimiento, escaneo de puertos y auditoría de redes esta está orientada a la ciberseguridad para descubrir y analizar la conectividad de red mediante sockets desde la línea de comandos.

# **Modulos planeados**
- **scanner.py:** Oswaldo Nabat Aranda Correa 
- **port_scanner.py:** Angel Eduardo Guevara Cruz
- **sniffer.py:** Angel Emmanuel García Ibarra
- **pcap_analyzer.py:** Gretel Denisse Manzo Medina
- **interoperabilidad.py:** Equipo
- **network_utils.py:** Kimberly Brisseyda Mata Ojeda
- **main.py:** Andrea Reyes Silva

# **CLI**
## network_utils.py

Utilidades de validación y resolución de red. Antes de ejecutar cualquier operación, PortLock valida los datos que escribe el usuario y muestra un mensaje de error claro si algo es incorrecto.

| Función | Qué hace | Devuelve | Errores |
| --- | --- | --- | --- |
| `es_ip_valida(texto)` | Indica si un texto es una IPv4 válida | `True` o `False` | Ninguno |
| `resolver_dominio(dominio)` | Resuelve un dominio a su IPv4 | La IPv4 en texto | `ValueError` |
| `preparar_objetivo(entrada)` | Recibe una IP o dominio y devuelve una IPv4 lista para el escáner | La IPv4 en texto | `ValueError` |
| `validar_ip(ip_str)` | Valida una IP o un rango CIDR, por ejemplo `192.168.1.0/24` | `True` | `ValueError` |
| `validar_puerto(puerto)` | Valida un puerto entre 1 y 65535 | El puerto como entero | `ValueError` |
| `validar_rango_puertos(rango)` | Valida un puerto único (`80`) o un rango (`1-1024`) | `(inicio, fin)` | `ValueError` |
| `validar_archivo_salida(ruta)` | Verifica que el directorio de salida exista y se pueda escribir | `True` | `FileNotFoundError`, `PermissionError` |

Ejemplos de error:

- `validar_ip("999.1.1.1")` lanza `ValueError: IP/CIDR inválido: '999.1.1.1'`
- `validar_puerto("0")` lanza `ValueError: Puerto fuera de rango: 0 (debe ser 1-65535).`
- `validar_rango_puertos("80-20")` lanza `ValueError: Rango inválido: 80 es mayor que 20.`
  
