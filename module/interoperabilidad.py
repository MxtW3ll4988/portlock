"""Módulo de interoperabilidad.
 
Detecta el sistema operativo, ejecuta el script nativo correspondiente
(PowerShell en Windows, Bash en Linux/macOS), captura la salida como
datos estructurados y genera un reporte con los resultados.
 
Ambos scripts producen la misma estructura de secciones, por lo que los
resultados son equivalentes sin importar el sistema operativo.
"""
 
import base64
import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path
 
# Marcador que separa cada sección en la salida de los scripts
SECTION_MARKER = "###"
 
# Secciones de información que ambos scripts deben producir
SECTIONS = (
    "hostname",
    "current_user",
    "network_interfaces",
    "listening_ports",
    "active_processes",
    "active_services",
    "system_users",
)
 
# Secciones cuyo valor es un único texto en lugar de una lista
SCALAR_SECTIONS = ("hostname", "current_user")
 
SCRIPT_TIMEOUT = 120
 
POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
 
Write-Output '### hostname'
Write-Output $env:COMPUTERNAME
 
Write-Output '### current_user'
Write-Output $env:USERNAME
 
Write-Output '### network_interfaces'
Get-NetIPAddress | ForEach-Object {
    "{0} {1}" -f $_.InterfaceAlias, $_.IPAddress
}
 
Write-Output '### listening_ports'
Get-NetTCPConnection -State Listen | ForEach-Object {
    "{0}:{1} pid={2}" -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess
}
 
Write-Output '### active_processes'
Get-Process | ForEach-Object {
    "{0} {1}" -f $_.Id, $_.ProcessName
}
 
Write-Output '### active_services'
Get-Service | Where-Object Status -eq 'Running' | ForEach-Object {
    "{0} {1}" -f $_.Name, $_.DisplayName
}
 
Write-Output '### system_users'
Get-LocalUser | ForEach-Object {
    "{0} enabled={1}" -f $_.Name, $_.Enabled
}
"""
 
BASH_SCRIPT = r"""
echo '### hostname'
hostname 2>/dev/null
 
echo '### current_user'
whoami 2>/dev/null
 
echo '### network_interfaces'
(ip addr 2>/dev/null || ifconfig 2>/dev/null) || true
 
echo '### listening_ports'
(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null \
    || netstat -an -p tcp 2>/dev/null | grep LISTEN) || true
 
echo '### active_processes'
ps aux 2>/dev/null
 
echo '### active_services'
(systemctl list-units --type=service --state=running 2>/dev/null \
    || launchctl list 2>/dev/null) || true
 
echo '### system_users'
cat /etc/passwd 2>/dev/null
"""
 
 
def detect_os():
    """Devuelve el nombre del sistema operativo (Windows, Linux, Darwin)."""
    return platform.system()
 
 
def get_command(os_name):
    """Devuelve el comando a ejecutar según el sistema operativo."""
    if os_name == "Windows":
        # EncodedCommand evita problemas de comillas al pasar el script
        encoded = base64.b64encode(
            POWERSHELL_SCRIPT.encode("utf-16-le")
        ).decode("ascii")
        return [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ]
    if os_name in ("Linux", "Darwin"):
        return ["bash", "-c", BASH_SCRIPT]
    raise RuntimeError("Unsupported operating system: " + os_name)
 
 
def run_script(os_name):
    """Ejecuta el script nativo y devuelve (salida, errores, código)."""
    command = get_command(os_name)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=SCRIPT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return "", "Shell not found: " + command[0], -1
    except subprocess.TimeoutExpired:
        return "", "Script timed out", -1
 
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    if os_name == "Windows":
        stderr = ""
    return stdout, stderr.strip(), completed.returncode
 
 
def parse_output(raw_output):
    """Convierte la salida del script en un diccionario estructurado."""
    data = {name: [] for name in SECTIONS}
    current = None
 
    for line in raw_output.splitlines():
        line = line.rstrip()
        if line.startswith(SECTION_MARKER):
            name = line[len(SECTION_MARKER):].strip()
            current = name if name in data else None
            continue
        if current is not None and line:
            data[current].append(line)
 
    for name in SCALAR_SECTIONS:
        data[name] = data[name][0] if data[name] else ""
 
    return data
 
 
def generate_report(result):
    """Genera un reporte de texto legible a partir del resultado."""
    lines = [
        "=" * 60,
        "SYSTEM ENUMERATION REPORT",
        "=" * 60,
        "Timestamp : " + result["timestamp"],
        "OS        : " + result["os"],
        "Success   : " + str(result["success"]),
        "",
    ]
 
    for name in SECTIONS:
        value = result["data"][name]
        lines.append("[" + name.upper() + "]")
        if isinstance(value, list):
            lines.append("Total: " + str(len(value)))
            lines.extend(value)
        else:
            lines.append(value)
        lines.append("")
 
    if result["errors"]:
        lines.append("[ERRORS]")
        lines.append(result["errors"])
 
    return "\n".join(lines)
 
 
def save_report(result, output_path):
    """Guarda el resultado: JSON si la extensión es .json, texto si no."""
    path = Path(output_path)
    if path.suffix.lower() == ".json":
        content = json.dumps(result, indent=4, ensure_ascii=False)
    else:
        content = generate_report(result)
    path.write_text(content, encoding="utf-8")
    return path
 
 
def enumeracion_sistema(output_path=None):
    """Enumeración defensiva del sistema.
 
    Detecta el SO, ejecuta el script correspondiente, captura la salida
    como datos estructurados y, si se indica una ruta, guarda el reporte.
    """
    os_name = detect_os()
    raw_output, errors, return_code = run_script(os_name)
 
    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "os": os_name,
        "return_code": return_code,
        "success": return_code == 0 and bool(raw_output.strip()),
        "errors": errors,
        "data": parse_output(raw_output),
    }
 
    if output_path:
        save_report(result, output_path)
 
    return result
 
 
# Alias por compatibilidad con el nombre usado en la evidencia de prueba
enumerar_sistema = enumeracion_sistema
 
 
if __name__ == "__main__":
    print(generate_report(enumeracion_sistema()))
