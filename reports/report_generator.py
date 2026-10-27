"""
Modulo de generacion de reportes.
Toma los resultados del escaneo (y la comparacion contra la linea base,
si existe) y genera un informe HTML legible y presentable.
"""

import os
from datetime import datetime


def _render_device_row(device):
    """Genera el HTML de una fila de la tabla para un dispositivo."""
    ports = device.get("open_ports", [])

    if ports:
        ports_html = "<br>".join(
            f"<span class='port'>{p['port']}</span> - {p['service_hint']}"
            for p in ports
        )
    else:
        ports_html = "<span class='no-ports'>Ninguno detectado</span>"

    mac_type_class = "mac-random" if device.get("mac_type") == "Aleatoria/Privada" else "mac-fixed"

    return f"""
    <tr>
        <td>{device['ip']}</td>
        <td><code>{device['mac']}</code></td>
        <td>{device.get('vendor', 'Desconocido')}</td>
        <td><span class="{mac_type_class}">{device.get('mac_type', '')}</span></td>
        <td>{ports_html}</td>
    </tr>
    """


def _render_comparison_section(comparison):
    """Genera el HTML de la seccion de comparacion contra la linea base."""
    if comparison is None:
        return "<p class='info'>No se realizo comparacion contra linea base en este escaneo.</p>"

    html = ""

    if comparison["new_devices"]:
        html += "<div class='alert'><h3>Dispositivos nuevos detectados</h3><ul>"
        for d in comparison["new_devices"]:
            html += f"<li>{d['ip']} ({d['mac']}) - {d.get('vendor', 'Desconocido')}</li>"
        html += "</ul></div>"
    else:
        html += "<p class='ok'>No se detectaron dispositivos nuevos.</p>"

    if comparison["missing_devices"]:
        html += "<div class='info-box'><h3>Dispositivos ausentes (estaban en la linea base)</h3><ul>"
        for d in comparison["missing_devices"]:
            html += f"<li>{d['ip']} ({d['mac']}) - {d.get('vendor', 'Desconocido')}</li>"
        html += "</ul></div>"

    if comparison["new_ports"]:
        html += "<div class='alert'><h3>Puertos nuevos en dispositivos conocidos</h3><ul>"
        for mac, info in comparison["new_ports"].items():
            html += f"<li>{info['ip']} ({mac}): puertos {info['ports']}</li>"
        html += "</ul></div>"
    else:
        html += "<p class='ok'>Ningun dispositivo conocido abrio puertos nuevos.</p>"

    return html


def _render_findings_section(findings):
    """Genera el HTML de la seccion de hallazgos de hardening."""
    if not findings:
        return "<p class='ok'>No se generaron recomendaciones. Buen estado general.</p>"

    severity_class = {
        "alta": "sev-alta",
        "media": "sev-media",
        "baja": "sev-baja",
        "informativa": "sev-info",
    }

    html = ""
    for f in findings:
        css_class = severity_class.get(f["severity"], "sev-info")
        html += f"""
        <div class="finding {css_class}">
            <div class="finding-header">
                <span class="severity-badge">{f['severity'].upper()}</span>
                <strong>{f['title']}</strong>
            </div>
            <div class="finding-device">Dispositivo: {f['ip']} ({f['vendor']})</div>
            <div class="finding-rec">{f['recommendation']}</div>
        </div>
        """

    return html


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Sentinel - Informe de Auditoria de Red</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f4f6f8; color: #1a1a1a; }}
    h1 {{ color: #1a2b4c; }}
    h2 {{ color: #2c3e50; border-bottom: 2px solid #ddd; padding-bottom: 6px; margin-top: 40px; }}
    .meta {{ color: #666; font-size: 0.9em; margin-bottom: 30px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid #eee; }}
    th {{ background: #1a2b4c; color: white; }}
    tr:hover {{ background: #f9fafb; }}
    .mac-random {{ color: #b8860b; font-weight: 600; }}
    .mac-fixed {{ color: #2e7d32; }}
    .port {{ background: #e8eef7; padding: 1px 6px; border-radius: 3px; font-family: monospace; }}
    .no-ports {{ color: #999; font-style: italic; }}
    .alert {{ background: #fdecea; border-left: 4px solid #d32f2f; padding: 12px 16px; margin: 12px 0; }}
    .info-box {{ background: #e8f0fe; border-left: 4px solid #1565c0; padding: 12px 16px; margin: 12px 0; }}
    .ok {{ color: #2e7d32; }}
    .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
    .summary-card {{ background: white; padding: 16px 24px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .summary-card .number {{ font-size: 2em; font-weight: bold; color: #1a2b4c; }}
    .finding {{ background: white; border-left: 5px solid #ccc; border-radius: 4px; padding: 12px 16px; margin: 10px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    .finding-header {{ margin-bottom: 6px; }}
    .severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.75em; font-weight: bold; color: white; margin-right: 8px; }}
    .sev-alta {{ border-left-color: #d32f2f; }}
    .sev-alta .severity-badge {{ background: #d32f2f; }}
    .sev-media {{ border-left-color: #f57c00; }}
    .sev-media .severity-badge {{ background: #f57c00; }}
    .sev-baja {{ border-left-color: #fbc02d; }}
    .sev-baja .severity-badge {{ background: #fbc02d; color: #333; }}
    .sev-info {{ border-left-color: #1565c0; }}
    .sev-info .severity-badge {{ background: #1565c0; }}
    .finding-device {{ color: #555; font-size: 0.9em; margin-bottom: 4px; }}
    .finding-rec {{ font-size: 0.95em; }}
</style>
</head>
<body>
    <h1>Sentinel — Informe de Auditoria de Red</h1>
    <p class="meta">Generado el {timestamp} | Red escaneada: {network_range}</p>

    <div class="summary">
        <div class="summary-card">
            <div class="number">{device_count}</div>
            <div>Dispositivos activos</div>
        </div>
        <div class="summary-card">
            <div class="number">{open_ports_count}</div>
            <div>Puertos abiertos totales</div>
        </div>
    </div>

    <h2>Dispositivos detectados</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>MAC</th>
            <th>Fabricante</th>
            <th>Tipo de MAC</th>
            <th>Puertos abiertos</th>
        </tr>
        {device_rows}
    </table>

    <h2>Comparacion contra linea base</h2>
    {comparison_section}

    <h2>Recomendaciones de hardening</h2>
    {findings_section}

</body>
</html>
"""


def generate_report(devices, comparison=None, network_range="192.168.1.1/24",
                     output_dir="reports", findings=None):
    """
    Genera un informe HTML con los resultados del escaneo actual,
    opcionalmente incluyendo la comparacion contra la linea base.
    Guarda el archivo con un nombre que incluye fecha y hora, para
    no sobrescribir reportes anteriores.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now()
    device_rows = "\n".join(_render_device_row(d) for d in devices)
    open_ports_count = sum(len(d.get("open_ports", [])) for d in devices)
    comparison_section = _render_comparison_section(comparison)
    findings_section = _render_findings_section(findings or [])

    html = REPORT_TEMPLATE.format(
        timestamp=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        network_range=network_range,
        device_count=len(devices),
        open_ports_count=open_ports_count,
        device_rows=device_rows,
        comparison_section=comparison_section,
        findings_section=findings_section,
    )

    filename = f"reporte_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nInforme HTML generado: {filepath}")
    return filepath


"By: Slim2"