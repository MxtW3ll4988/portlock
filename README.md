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
- **utils.py:** Kimbelry Brisseyda Mata Ojeda
- **reporte.py** Equipo
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

## **pcap_analyzer.py**

Utilidades de análisis forense y lectura de archivos de captura de tráfico para PortLock.

| Función | Qué hace | Devuelve | Errores |
| --- | --- | --- | --- |
| `leer_archivo_pcap(ruta_archivo)` | Lee un archivo pcap y devuelve la lista de paquetes capturados | Lista de paquetes de Scapy o lista vacía | `FileNotFoundError`, `Scapy_Exception` |
| `filtrar_por_protocolo(paquetes, protocolo)` | Filtra los paquetes capturados según una capa o protocolo específico | Subconjunto de paquetes filtrados | `Exception` |
| `generar_resumen_trafico(paquetes)` | Imprime un resumen básico de las direcciones IP origen y destino | Ninguno (imprime en consola) | `Exception` |

## **scanner.py**

Escaneo de puertos TCP con Scapy (escaneo SYN). Envía un paquete SYN a cada puerto y considera abierto el que responde con SYN-ACK. Requiere privilegios de administrador (sudo) para enviar paquetes.

|Función |	Qué hace |	Devuelve |	Errores |
| --- | --- | --- | --- |
| `validar_puerto(puerto)` |	Indica si el puerto es un entero entre 1 y 65535	| `True` o `False` |	Ninguno |
| `escanear_puerto(ip, puerto)` |	Envía un SYN a un puerto y revisa la respuesta	| `True` si está abierto, `False` si no |	Ninguno (captura `PermissionError` y avisa que se requiere `sudo`) |
| `escanear_rango(ip, inicio, fin)` |	Escanea un rango de puertos (fin incluido) |	Lista de puertos abiertos |	Ninguno |

Ejemplos:

`escanear_puerto("127.0.0.1", 0)` devuelve `False` sin enviar ningún paquete (puerto fuera de 1-65535)
`escanear_rango("192.168.1.1", 20, 25)` devuelve una lista como `[22]` con los puertos abiertos

## **utils.py**

Funciones auxiliares compartidas entre los módulos de PortLock.

| Función | Qué hace |
| --- | --- |
| `timestamp_actual()` | Devuelve la fecha y hora actual en formato ISO 8601 |
| `medir_tiempo(func)` | Decorador que imprime cuánto tarda en ejecutarse una función |
| `imprimir_banner(nombre, version)` | Imprime el banner de la librería al iniciar |

## **reportes.py** 
Generación de reportes de PortLock en JSON y CSV.

| Función | Qué hace | Devuelve | Errores |
| --- | --- | --- | --- |
| `guardar_reporte(datos, ruta_salida, formato="json")` | Guarda los resultados en un archivo `json` o `csv` | `True` | `ValueError`, `FileNotFoundError`, `PermissionError`, `OSError` |

`datos` es un diccionario con las llaves `parametros` (diccionario), `resultados` (lista de diccionarios) y `errores` (lista). El reporte incluye la fecha y hora de generación y el total de resultados, y valida la ruta de salida con `validar_archivo_salida`.

## **interoperabilidad.py**
Enumeración defensiva del sistema. Detecta el sistema operativo, ejecuta el script nativo correspondiente (PowerShell en Windows, Bash en Linux/macOS), captura la salida como datos estructurados y genera un reporte. Los scripts van integrados en el módulo como cadenas de texto y ambos producen las mismas secciones, por lo que los resultados son equivalentes en cualquier sistema.

Información que recopila:

| Sección | PowerShell (Windows) | Bash (Linux/macOS) |
| --- | --- | --- |
| `hostname` | `$env:COMPUTERNAME` | `hostname` |
| `current_user` | `$env:USERNAME` | `whoami` |
| `network_interfaces` | `Get-NetIPAddress` | `ip addr` / `ifconfig` |
| `listening_ports` | `Get-NetTCPConnection -State Listen` | `ss -tlnp` / `netstat -tlnp` |
| `active_processes` | `Get-Process` | `ps aux` |
| `active_services` | `Get-Service` (en ejecución) | `systemctl list-units` |
| `system_users` | `Get-LocalUser` | `cat /etc/passwd` |

| Función | Qué hace | Devuelve |
| --- | --- | --- |
| `detect_os()` | Detecta el sistema operativo | `Windows`, `Linux` o `Darwin` |
| `get_command(os_name)` | Arma el comando del script según el sistema | Lista con el comando (`RuntimeError` si el sistema no es compatible) |
| `run_script(os_name)` | Ejecuta el script nativo | Tupla `(salida, errores, código)` |
| `parse_output(raw_output)` | Convierte la salida en datos estructurados | Diccionario por sección |
| `generate_report(result)` | Genera un reporte de texto legible | Texto |
| `save_report(result, output_path)` | Guarda el resultado: JSON si la ruta termina en `.json`, texto en otro caso | Ruta del archivo |
| `enumeracion_sistema(output_path=None)` | Ejecuta todo el proceso y, si se indica una ruta, guarda el reporte | Diccionario con `timestamp`, `os`, `return_code`, `success`, `errors` y `data` |
| `enumerar_sistema(output_path=None)` | Alias de `enumeracion_sistema` | Igual que la anterior |

Ejemplo de uso:

```python
from module.interoperabilidad import enumerar_sistema

resultado = enumerar_sistema("enum.json")
print(resultado["os"], resultado["data"]["hostname"])
```

También se puede ejecutar directo para ver el reporte en pantalla:

```bash
python -m module.interoperabilidad
```


## **Requisitos e instalación**

- Python 3
- Dependencias: se instalan desde `requirements.txt` (incluye Scapy para el sniffer y el análisis de PCAP)

```bash
git clone <URL del repositorio>
cd portlock
pip install -r requirements.txt
```

Notas:

- Los subcomandos `syn` y `sniffer` requieren privilegios de administrador.
- En Windows, la captura de tráfico en vivo necesita Npcap. Si no está instalado, aparece el aviso `No libpcap provider available`, que no afecta al resto de las funciones.

# **Uso desde la línea de comandos**

PortLock permite realizar una enumeración defensiva del sistema desde la terminal mediante el archivo `main.py`.

### Enumeración del sistema

Para ejecutar la enumeración y guardar los resultados en un archivo JSON:

```bash
python main.py enumerar --output evidencias/enum.json
```

El programa detecta el sistema operativo y recopila información del equipo, incluyendo:

- Nombre del equipo (hostname).
- Usuario actual.
- Interfaces de red.
- Puertos en escucha.
- Procesos activos.
- Servicios activos.
- Usuarios del sistema.

El resultado se guarda en la ruta especificada mediante `--output`. Si no se indica una ruta, se utiliza `enum.json`.

### Ejecución del menú interactivo

Para iniciar el menú principal de PortLock:

```bash
python main.py
```
Ver todos los comandos disponibles:

```bash
python main_argparse.py --help
```

| Subcomando | Qué hace |
| --- | --- |
| `scan` | Comprueba un puerto TCP |
| `scan-range` | Comprueba un rango de puertos TCP |
| `syn` | Ejecuta un escaneo SYN con Scapy |
| `sniffer` | Captura tráfico de red |
| `pcap` | Analiza un archivo PCAP |
| `pcap-filter` | Filtra un PCAP por protocolo |

Opciones de `scan`: `--target`, `--port`, `--format {json,csv}` y `--output`.

Opciones de `scan-range`: `--target`, `--start-port`, `--end-port`, `--format {json,csv}` y `--output`.

Ejemplos:

```bash
python main_argparse.py scan --target 127.0.0.1 --port 80 --output prueba.json
python main_argparse.py scan-range --target 127.0.0.1 --start-port 1 --end-port 100 --format csv --output rango.csv
```

| Opción | Qué hace |
| --- | --- |
| `1` | Escaneo de un puerto TCP (sockets) |
| `2` | Escaneo de un rango de puertos (sockets) |
| `3` | Escaneo SYN con Scapy |
| `4` | Captura de tráfico de red (sniffer) |
| `5` | Análisis de un archivo PCAP |
| `6` | Filtrado de un PCAP por protocolo |
| `7` | Salir |

En cada opción, el programa pregunta si se quiere guardar el reporte y en qué formato (`json` o `csv`). Antes de ejecutar una operación se validan el objetivo, los puertos y la ruta de salida (ver la sección de `network_utils.py`), y si algo es incorrecto se muestra un mensaje de error claro.

# Pruebas automatizadas

PortLock utiliza `pytest` para verificar el funcionamiento de sus módulos mediante pruebas automatizadas.

Los archivos de prueba incluyen:

- `module/test_network_utils.py`
- `module/test_utils.py`
- `module/test_interoperabilidad.py`
- `module/test_reportes.py`
- `module/test_port_scanner.py`
- `module/test_scanner.py`
- `module/test_sniffer.py`
- `module/test_pcap_analyzer.py`

Para ejecutar todas las pruebas desde la carpeta raíz del proyecto:

```bash
python -m pytest -v
```

**Resultado:** 42 pruebas aprobadas.

python -m module.interoperabilidad
python main.py enumerar --output evidencias/enum.json

Las pruebas verifican funciones de validación, interoperabilidad entre sistemas operativos, generación de reportes, escaneo de puertos, captura de tráfico y análisis de archivos PCAP.

# **Prueba de humo**

Comando para verificar que la librería se importa correctamente:

```bash
python -c "import module; print(module.__version__)"
```

Resultado:
<img width="998" height="111" alt="image" src="https://github.com/user-attachments/assets/185ad2a1-b50b-46c2-b9f8-4b9b4122dc31" />

Generar un reporte con datos reales desde el CLI:

```bash
python main_argparse.py scan --target 127.0.0.1 --port 80 --output prueba.json
```

Resultado:
<img width="1749" height="277" alt="image" src="https://github.com/user-attachments/assets/d3ea1c7c-0c39-4f8c-ac04-7df8323701e7" />

# **Evidencia de ejecución**

Salida real de `enumerar_sistema()` ejecutada en Windows, en el equipo de Kimberly Brisseyda Mata Ojeda (se muestra el inicio del reporte):

```bash
python -m module.interoperabilidad
```
<img width="855" height="399" alt="image" src="https://github.com/user-attachments/assets/5e4a6cd6-d6e6-4e20-beba-9bf78eab605d" />

---

##  Uso y licencia

PortLock se desarrolló con fines **educativos** como proyecto integrador de la materia. Puedes consultarlo, usarlo y modificarlo como referencia para aprender, siempre que conserves el aviso de copyright. Se distribuye bajo la **licencia MIT**; consulta el archivo `LICENSE` para más detalles.

Todo el código aquí publicado sigue el principio visto en clase: **la misma herramienta que sirve para auditar puede usarse mal — el contexto, la autorización y la intención son lo que determina su uso correcto.** Escanea puertos, captura tráfico y enumera sistemas **únicamente en equipos y redes propios o con autorización expresa** (por ejemplo `127.0.0.1` o un laboratorio designado), nunca en hosts ajenos. El equipo no se hace responsable del uso indebido de esta herramienta. Úsala de forma responsable.

PortLock depende de [Scapy](https://scapy.net/), un proyecto independiente con su propia licencia.
