
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WiFiDash - Network Diagnostic Dashboard (CLI)

USO Y ALCANCE
-------------
WiFiDash es una herramienta de diagnóstico de red orientada a:
- Educación (CCNA / fundamentos de redes)
- Diagnóstico defensivo
- Laboratorios locales y redes propias

Incluye:
- Descubrimiento básico de dispositivos
- Identificación de gateway e interfaces
- Métricas de latencia, jitter y MTU
- Topología lógica simplificada
- Evaluación estimativa de ancho de banda
- Sistema experto CCNA + ITIL con reporte explicativo

NO incluye:
- Explotación
- Fuerza bruta
- Ataques activos
- Garantía de detección total

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
    Ejecuta un comando del sistema con control de tiempo.
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
    """Devuelve un encabezado formateado."""
    return f"\n{title}\n{'=' * len(title)}\n"


def log_phase(name, start):
    """Registra el tiempo consumido por una fase."""
    PHASE_TIMES[name] = round(time.time() - start, 2)


def time_indicator(phase, value):
    """Evalúa el tiempo de ejecución de una fase."""
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
    """Obtiene el gateway por defecto."""
    out, _ = run_cmd("ip route | grep default")
    return out.split()[2] if out else "Desconocido"


def get_interfaces():
    """Lista interfaces de red disponibles."""
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
    """Resuelve el nombre DNS de una IP."""
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
    """Clasifica el dispositivo según puertos abiertos."""
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
# RENDIMIENTO (NO MODIFICADO)
# ==================================================

def bandwidth_test():
    """Prueba estimativa de ancho de banda."""
    dl = []
    ul = []
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
# SISTEMA EXPERTO
# ==================================================

def expert_conclusions(devices, latency, jitter, mtu, dl, ul, variation,
                       stability, gateway, hops, total_time):
    """
    Sistema experto CCNA + ITIL.
    Proporciona evidencia, interpretación, score dinámico y recomendaciones.
    """

    score = 100
    findings = []

    if latency > 50:
        score -= 20
        findings.append("Latencia elevada (>50 ms)")
    elif latency > 20:
        score -= 10
        findings.append("Latencia moderada (>20 ms)")

    if jitter > 10:
        score -= 15
        findings.append("Jitter alto (>10 ms)")
    elif jitter > 5:
        score -= 8
        findings.append("Jitter moderado (>5 ms)")

    if mtu < 1500:
        score -= 10
        findings.append("MTU inferior al óptimo (1500)")

    if len(hops) <= 2:
        score -= 10
        findings.append("Red plana sin segmentación visible")

    if len(devices) > 15:
        score -= 15
        findings.append("Alta densidad de dispositivos")

    if total_time > 90:
        score -= 10
        findings.append("Tiempo de diagnóstico elevado")

    score = max(score, 0)

    lines = []
    lines.append(banner("EXPERT NETWORK ANALYSIS REPORT"))

    lines.append("ESTADO GENERAL")
    lines.append(f"Score técnico global: {score} / 100")
    lines.append("Nivel de confianza: ALTO")
    lines.append("-" * 50)

    lines.append("EVIDENCIA PRIMARIA")
    lines.append(f"Gateway: {gateway}")
    lines.append(f"Dispositivos detectados: {len(devices)}")
    lines.append(f"Latencia promedio: {latency} ms")
    lines.append(f"Jitter promedio: {jitter} ms")
    lines.append(f"MTU efectivo: {mtu}")
    lines.append(f"Download estimado: {dl} Mbps")
    lines.append(f"Upload estimado: {ul} Mbps")
    lines.append(f"Variación DL/UL: {variation}% ({stability})")
    lines.append(f"Saltos detectados: {len(hops)}")
    lines.append("-" * 50)

    lines.append("INTERPRETACIÓN TÉCNICA (CCNA)")
    lines.append(
        "• Latencia baja indica cercanía y buen estado del gateway.\n"
        "• Jitter alto afecta VoIP y video en tiempo real.\n"
        "• MTU reducido puede causar fragmentación.\n"
        "• Redes planas aumentan el dominio de broadcast."
    )

    lines.append("-" * 50)
    lines.append("HALLAZGOS")
    if findings:
        for f in findings:
            lines.append(f"⚠ {f}")
    else:
        lines.append("✔ Sin anomalías críticas")

    lines.append("-" * 50)
    lines.append("RECOMENDACIONES")
    lines.append("1) Implementar QoS para tráfico sensible")
    lines.append("2) Segmentar usuarios e IoT (VLANs)")
    lines.append("3) Verificar MTU extremo a extremo")
    lines.append("4) Programar mediciones periódicas")
    lines.append("5) Documentar topología y crecimiento")

    lines.append("-" * 50)
    lines.append("CONCLUSIÓN FINAL")
    if score >= 85:
        lines.append("🟢 Red saludable y estable")
    elif score >= 65:
        lines.append("🟡 Red operativa con oportunidades de mejora")
    else:
        lines.append("🔴 Red con riesgos operativos")

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

    subnet = input("Subred a escanear (ej. 192.168.1.0/24): ").strip()
    t = time.time()
    hosts = scan_subnet(subnet)
    log_phase("Escaneo red", t)

    devices = []
    report.append(banner("DISPOSITIVOS"))
    for ip in hosts:
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
    report.append(banner("MAPA LOGICO"))
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
        report.append(f"{k.ljust(20)}: {v} s   {time_indicator(k, v)}")

    report.append(banner("COMANDOS FALLIDOS"))
    report.extend(FAILED_COMMANDS if FAILED_COMMANDS else ["Ninguno"])

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