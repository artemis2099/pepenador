
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WiFiDash - Network Diagnostic Dashboard (CLI)

USO Y ALCANCE
-------------
Esta herramienta realiza un diagnóstico técnico de una red local desde
un enfoque defensivo y educativo (CCNA / ITIL).

Incluye:
- Descubrimiento básico de dispositivos
- Métricas de latencia, jitter y MTU
- Topología lógica simplificada
- Evaluación estimativa de ancho de banda
- Sistema experto con recomendaciones técnicas

NO incluye:
- Explotación
- Fuerza bruta
- Análisis ofensivo
- Garantía de detección completa

⚠️ USAR SOLO EN REDES PROPIAS O AUTORIZADAS
Compatible con Linux y Termux (con limitaciones de permisos).
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
    "Escaneo red": 5.0,
    "Latencia/Jitter/MTU": 3.0,
    "Traceroute": 5.0,
    "Ancho de banda": 35.0,
    "Total": 60.0
}

COMMON_PORTS = [21, 22, 80, 443, 8080]

# ==================================================
# UTILIDADES
# ==================================================

def run_cmd(cmd, timeout=15):
    """
    Ejecuta un comando del sistema con timeout.
    Registra comandos fallidos para el reporte final.
    """
    try:
        start = time.time()
        out = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        ).decode().strip()
        return out, round(time.time() - start, 2)
    except Exception:
        FAILED_COMMANDS.append(cmd)
        return None, 0


def banner(title):
    """Devuelve un encabezado formateado para consola/reporte."""
    return f"\n{title}\n{'=' * len(title)}\n"


def log_phase(name, start):
    """Registra el tiempo de ejecución de una fase."""
    PHASE_TIMES[name] = round(time.time() - start, 2)


def time_indicator(phase, value):
    """Evalúa si el tiempo de una fase fue adecuado."""
    expected = EXPECTED_TIMES.get(phase, value)
    if value <= expected:
        return "🟢 BUENO"
    elif value <= expected * 1.5:
        return "🟡 REGULAR"
    else:
        return "🔴 MALO"


def render_bar(value, max_value=100, length=20):
    """Renderiza una barra ASCII proporcional."""
    filled = int(length * min(value, max_value) / max_value)
    return '█' * filled + ' ' * (length - filled)

# ==================================================
# IDENTIDAD DE RED
# ==================================================

def get_gateway():
    """Obtiene el gateway por defecto del sistema."""
    out, _ = run_cmd("ip route | grep default")
    return out.split()[2] if out else "Desconocido"


def get_interfaces():
    """Lista las interfaces de red disponibles."""
    out, _ = run_cmd("ip link")
    return out or "No disponible"

# ==================================================
# DESCUBRIMIENTO DE RED
# ==================================================

def scan_subnet(subnet):
    """
    Escanea una subred detectando hosts con puerto 80 abierto.
    Método ligero y compatible con entornos sin privilegios.
    """
    hosts = []
    for ip in ip_network(subnet, strict=False).hosts():
        ip = str(ip)
        s = socket.socket()
        s.settimeout(0.3)
        if s.connect_ex((ip, 80)) == 0:
            hosts.append(ip)
        s.close()
    return hosts


def resolve_hostname(ip):
    """Intenta resolver el nombre DNS de una IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def scan_ports(ip):
    """Escaneo limitado de puertos comunes."""
    open_ports = []
    for p in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(0.4)
        if s.connect_ex((ip, p)) == 0:
            open_ports.append(p)
        s.close()
    return open_ports


def classify_device(ports):
    """Clasifica el tipo de dispositivo según puertos abiertos."""
    if 22 in ports:
        return "Servidor / Linux"
    if 80 in ports or 443 in ports:
        return "Web / IoT"
    return "Dispositivo genérico"

# ==================================================
# MÉTRICAS INTERNAS
# ==================================================

def latency_jitter_mtu(target):
    """
    Calcula latencia promedio, jitter y MTU efectivo hacia un destino.
    """
    times = []
    for _ in range(5):
        out, _ = run_cmd(f"ping -c 1 -W 1 {target}")
        if out and "time=" in out:
            try:
                t = float(out.split("time=")[1].split()[0])
                times.append(t)
            except Exception:
                continue

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
    """Obtiene los primeros saltos hacia el gateway."""
    out, _ = run_cmd(f"traceroute -m 5 {target}", timeout=20)
    hops = []
    if out:
        for line in out.splitlines():
            if line and line[0].isdigit():
                parts = line.split()
                if len(parts) > 1:
                    hops.append(parts[1])
    return hops


def build_logical_map(gateway, devices, hops):
    """Construye un mapa lógico ASCII de la red."""
    lines = ["Internet"]
    prefix = " └─ "
    for i, hop in enumerate(hops):
        lines.append(f"{prefix}Hop {i+1}: {hop}")
        prefix += "    "
    lines.append(f"{prefix}Gateway: {gateway}")
    prefix += "    "
    if devices:
        for ip, dtype in devices:
            lines.append(f"{prefix}├─ {ip} [{dtype}]")
    else:
        lines.append(f"{prefix}(Sin dispositivos detectados)")
    return "\n".join(lines)

# ==================================================
# SISTEMA EXPERTO MEJORADO
# ==================================================

def expert_conclusions(devices, latency, jitter, mtu, dl, ul, variation,
                       stability, gateway, hops, total_time):
    """
    Sistema experto CCNA + ITIL con score dinámico y conclusiones
    basadas en evidencia real.
    """

    score = 100
    findings = []

    # Latencia
    if latency > 50:
        score -= 20
        findings.append("Latencia elevada")
    elif latency > 20:
        score -= 10

    # Jitter
    if jitter > 10:
        score -= 15
        findings.append("Jitter alto")
    elif jitter > 5:
        score -= 8

    # MTU
    if mtu < 1500:
        score -= 10
        findings.append("MTU subóptimo")

    # Topología
    if len(hops) <= 2:
        score -= 10
        findings.append("Red plana sin segmentación")

    # Densidad
    if len(devices) > 15:
        score -= 15
        findings.append("Alta densidad de dispositivos")

    # Tiempo total
    if total_time > 90:
        score -= 10

    score = max(score, 0)

    lines = []
    lines.append(banner("EXPERT NETWORK ANALYSIS REPORT"))
    lines.append(f"Score técnico global: {score} / 100")
    lines.append(f"Dispositivos detectados: {len(devices)}")
    lines.append(f"Gateway: {gateway}")
    lines.append("-" * 50)

    lines.append("HALLAZGOS CLAVE")
    if findings:
        for f in findings:
            lines.append(f"⚠ {f}")
    else:
        lines.append("✔ Sin anomalías críticas detectadas")

    lines.append("-" * 50)
    lines.append("RECOMENDACIONES PRIORITARIAS")
    lines.append("1) Implementar QoS si existe tráfico sensible")
    lines.append("2) Segmentar IoT y usuarios (VLANs)")
    lines.append("3) Monitoreo periódico de latencia y jitter")
    lines.append("4) Validar MTU extremo a extremo")

    lines.append("-" * 50)
    lines.append("CONCLUSIÓN FINAL")
    if score >= 85:
        lines.append("🟢 Red saludable y estable")
    elif score >= 65:
        lines.append("🟡 Red operativa con oportunidades de mejora")
    else:
        lines.append("🔴 Red con riesgos operativos")

    return "\n".join(lines)
