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

