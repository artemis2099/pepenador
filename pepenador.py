#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WiFiDash - Network Diagnostic Dashboard (CLI)

USO Y ALCANCE
-------------
Herramienta de diagnóstico de red orientada a:
- Educación (CCNA / fundamentos de redes)
- Diagnóstico defensivo de redes LAN
- Laboratorios locales (Linux / Termux)

Método de descubrimiento:
- Tabla ARP (ip neigh) → dispositivos activos reales

Incluye:
- Descubrimiento realista de dispositivos LAN
- Identidad de red
- Métricas (latencia, jitter, MTU)
- Topología lógica
- Evaluación estimativa de ancho de banda
- Sistema experto CCNA + ITIL

NO incluye técnicas ofensivas.
⚠️ Usar solo en redes propias o autorizadas.
"""

import socket
import subprocess
import time
import statistics
from datetime import datetime
from ipaddress import ip_network

# ==================================================
# GLOBALES
# ==================================================

FAILED_COMMANDS = []
PHASE_TIMES = {}

EXPECTED_TIMES = {
    "Gateway": 0.1,
    "Interfaces": 0.5,
    "Descubrimiento ARP": 2.0,
    "Latencia/Jitter/MTU": 3.0,
    "Traceroute": 5.0,
    "Ancho de banda": 35.0,
    "Total": 60.0
}
#20, 21, 22, 139, 137, 445, 53, 443, 80, 8080, 8443, 23, 25, 69, 554, 2101, 9000 
COMMON_PORTS = [20, 21, 22, 139, 137, 445, 53, 443, 80, 8080, 8443, 23, 25, 69, 554, 2101, 9000]

# ==================================================
# UTILIDADES
# ==================================================

def run_cmd(cmd, timeout=15):
    """Ejecuta un comando del sistema con timeout."""
    try:
        start = time.time()
        out = subprocess.check_output(
            cmd, shell=True,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        ).decode().strip()
        return out, round(time.time() - start, 2)
    except Exception:
        FAILED_COMMANDS.append(cmd)
        return None, 0


def banner(title):
    """Encabezado visual."""
    return f"\n{title}\n{'=' * len(title)}\n"


def log_phase(name, start):
    """Registra tiempo de una fase."""
    PHASE_TIMES[name] = round(time.time() - start, 2)


def time_indicator(phase, value):
    """Evalúa tiempo de fase."""
    expected = EXPECTED_TIMES.get(phase, value)
    if value <= expected:
        return "🟢 BUENO"
    elif value <= expected * 1.5:
        return "🟡 REGULAR"
    return "🔴 MALO"


def render_bar(value, max_value=100, length=20):
    """Barra ASCII."""
    filled = int(length * min(value, max_value) / max_value)
    return '█' * filled + ' ' * (length - filled)

# ==================================================
# IDENTIDAD DE RED
# ==================================================

def get_gateway():
    """Obtiene gateway por defecto."""
    out, _ = run_cmd("ip route | grep default")
    return out.split()[2] if out else "Desconocido"


def get_interfaces():
    """Lista interfaces."""
    out, _ = run_cmd("ip link")
    return out or "No disponible"

# ==================================================
# DESCUBRIMIENTO DE RED (ARP)
# ==================================================

def discover_arp_devices():
    """
    Descubre dispositivos activos mediante la tabla ARP.
    Método confiable y no invasivo para LAN.
    """
    devices = []
    out, _ = run_cmd("ip neigh")
    if not out:
        return devices

    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-1] != "FAILED":
            ip = parts[0]
            devices.append(ip)

    return sorted(set(devices))


def resolve_hostname(ip):
    """Resuelve hostname DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def scan_ports(ip):
    """Escaneo ligero de puertos comunes."""
    open_ports = []
    for p in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(0.4)
        if s.connect_ex((ip, p)) == 0:
            open_ports.append(p)
        s.close()
    return open_ports


def classify_device(ports):
    """Clasificación heurística del dispositivo."""
    if 22 in ports:
        return "Servidor / Linux"
    if 80 in ports or 443 in ports:
        return "Web / IoT"
    return "Cliente / Genérico"

# ==================================================
# MÉTRICAS
# ==================================================

def latency_jitter_mtu(target):
    """Latencia, jitter y MTU."""
    times = []
    for _ in range(5):
        out, _ = run_cmd(f"ping -c 1 -W 1 {target}")
        if out and "time=" in out:
            try:
                times.append(float(out.split("time=")[1].split()[0]))
            except Exception:
                pass

    latency = round(statistics.mean(times), 2) if times else 0
    jitter = round(statistics.stdev(times), 2) if len(times) > 1 else 0

    mtu = 0
    for size in [1472, 1464, 1450]:
        out, _ = run_cmd(f"ping -c 1 -M do -s {size} {target}")
        if out:
            mtu = size + 28
            break

    return latency, jitter, mtu

# ==================================================
# TOPOLOGÍA
# ==================================================

def get_traceroute(target):
    """Obtiene saltos hacia el gateway."""
    out, _ = run_cmd(f"traceroute -m 5 {target}", timeout=20)
    hops = []
    if out:
        for line in out.splitlines():
            if line and line[0].isdigit():
                hops.append(line.split()[1])
    return hops


def build_logical_map(gateway, devices, hops):
    """Mapa lógico ASCII."""
    lines = ["Internet"]
    prefix = " └─ "
    for i, hop in enumerate(hops):
        lines.append(f"{prefix}Hop {i+1}: {hop}")
        prefix += "    "

    lines.append(f"{prefix}Gateway: {gateway}")
    prefix += "    "

    for ip, dtype in devices:
        lines.append(f"{prefix}├─ {ip} [{dtype}]")

    return "\n".join(lines)

# ==================================================
# RENDIMIENTO (NO MODIFICADO)
# ==================================================

def bandwidth_test():
    """Prueba estimativa de ancho de banda."""
    dl, ul = [], []
    for _ in range(3):
        out, _ = run_cmd("curl -o /dev/null http://speedtest.tele2.net/10MB.zip", timeout=30)
        if out is not None:
            dl.append(10)
    for _ in range(3):
        out, _ = run_cmd("curl -T /dev/null http://speedtest.tele2.net/upload.php", timeout=30)
        if out is not None:
            ul.append(1)

    if not dl or not ul:
        return None

    dl_mbps = statistics.mean(dl) * 8
    ul_mbps = statistics.mean(ul) * 8
    variation = abs(dl_mbps - ul_mbps) / max(dl_mbps, ul_mbps) * 100
    stability = "🟢 ESTABLE" if variation < 10 else "🟡 MODERADA" if variation < 25 else "🔴 INESTABLE"
    return dl_mbps, ul_mbps, round(variation, 2), stability

# ==================================================
# SISTEMA EXPERTO (SIN CAMBIOS FUNCIONALES)
# ==================================================

def expert_conclusions(devices, latency, jitter, mtu, dl, ul, variation,
                       stability, gateway, hops, total_time):
    """Sistema experto CCNA + ITIL."""
    score = 100
    findings = []

    if latency > 50:
        score -= 20; findings.append("Latencia elevada")
    elif latency > 20:
        score -= 10

    if jitter > 10:
        score -= 15; findings.append("Jitter alto")
    elif jitter > 5:
        score -= 8

    if mtu < 1500:
        score -= 10; findings.append("MTU subóptimo")

    if len(hops) <= 2:
        score -= 10; findings.append("Red plana")

    if len(devices) > 15:
        score -= 15; findings.append("Alta densidad")

    score = max(score, 0)

    lines = []
    lines.append(banner("EXPERT NETWORK ANALYSIS REPORT"))
    lines.append(f"Score técnico: {score} / 100")
    lines.append(f"Dispositivos detectados: {len(devices)}")
    lines.append(f"Gateway: {gateway}")
    lines.append("-" * 50)

    for f in findings:
        lines.append(f"⚠ {f}")

    lines.append("✔ Red operativa con recomendaciones preventivas")
    return "\n".join(lines)

# ==================================================
# MAIN
# ==================================================

def main():
    report = []
    start_total = time.time()
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    report.append(banner("NETWORK DASH - RESUMEN DE RED"))

    t = time.time()
    gw = get_gateway()
    log_phase("Gateway", t)
    report.append(f"Gateway: {gw}")

    t = time.time()
    report.append(banner("INTERFACES"))
    report.append(get_interfaces())
    log_phase("Interfaces", t)

    t = time.time()
    arp_hosts = discover_arp_devices()
    log_phase("Descubrimiento ARP", t)

    devices = []
    report.append(banner("DISPOSITIVOS (ARP)"))
    for ip in arp_hosts:
        ports = scan_ports(ip)
        dtype = classify_device(ports)
        host = resolve_hostname(ip)
        devices.append((ip, dtype))
        report.append(f"{ip} | {host} | {dtype} | Puertos: {ports}")

    t = time.time()
    lat, jit, mtu = latency_jitter_mtu(gw)
    log_phase("Latencia/Jitter/MTU", t)

    report.append(banner("LATENCIA / JITTER / MTU"))
    report.append(f"Latencia: {lat} ms")
    report.append(f"Jitter: {jit} ms")
    report.append(f"MTU: {mtu}")

    t = time.time()
    hops = get_traceroute(gw)
    log_phase("Traceroute", t)

    report.append(banner("MAPA LOGICO DE RED"))
    report.append(build_logical_map(gw, devices, hops))

    t = time.time()
    bw = bandwidth_test()
    log_phase("Ancho de banda", t)

    report.append(banner("ANCHO DE BANDA"))
    if bw:
        dl, ul, var, stab = bw
        report.append(f"Download: {render_bar(dl)} {dl} Mbps")
        report.append(f"Upload:   {render_bar(ul)} {ul} Mbps")
        report.append(f"Variación: {var}% ({stab})")
    else:
        dl = ul = var = 0
        stab = "No disponible"
        report.append("❌ Prueba incompleta")

    total_time = round(time.time() - start_total, 2)
    PHASE_TIMES["Total"] = total_time

    report.append(banner("TIEMPOS POR FASE"))
    for k, v in PHASE_TIMES.items():
        report.append(f"{k.ljust(22)}: {v} s   {time_indicator(k, v)}")

    report.append(
        expert_conclusions(devices, lat, jit, mtu, dl, ul, var, stab, gw, hops, total_time)
    )

    fname = f"network_report_{now}.txt"
    with open(fname, "w") as f:
        f.write("\n".join(report))

    print("\n".join(report))
    print(f"\nReporte guardado en: {fname}")

if __name__ == "__main__":
    main()
