"""
Modulo de hardening.
Motor de reglas que analiza los dispositivos detectados y genera
recomendaciones de seguridad concretas, cada una con un nivel de
severidad (alta, media, baja, informativa).
"""


SEVERITY_ORDER = {"alta": 0, "media": 1, "baja": 2, "informativa": 3}


def _finding(device, severity, title, recommendation):
    """Crea un diccionario estandarizado para un hallazgo de hardening."""
    return {
        "ip": device["ip"],
        "mac": device["mac"],
        "vendor": device.get("vendor", "Desconocido"),
        "severity": severity,
        "title": title,
        "recommendation": recommendation,
    }


def _check_ssh(device, findings):
    """Regla 1: puerto 22 (SSH) abierto."""
    for p in device.get("open_ports", []):
        if p["port"] == 22:
            findings.append(_finding(
                device, "media",
                "Puerto SSH (22) abierto",
                "Verifica si el acceso SSH esta expuesto a internet (WAN) o solo "
                "a tu red local (LAN). Si no usas SSH activamente, considera "
                "desactivarlo. Si lo usas, prefiere autenticacion por llave "
                "en vez de contrasena."
            ))


def _check_telnet(device, findings):
    """Regla 2: puerto 23 (Telnet) abierto - siempre critico."""
    for p in device.get("open_ports", []):
        if p["port"] == 23:
            findings.append(_finding(
                device, "alta",
                "Puerto Telnet (23) abierto",
                "Telnet transmite datos sin cifrar, incluidas contrasenas. "
                "Deberia desactivarse y reemplazarse por SSH si se necesita "
                "acceso remoto por terminal."
            ))


def _check_admin_panels(device, findings):
    """Regla 3: puertos 8080/8443/80/443 (paneles de administracion web)."""
    admin_ports = {80, 443, 8080, 8443}
    for p in device.get("open_ports", []):
        if p["port"] in admin_ports:
            findings.append(_finding(
                device, "media",
                f"Posible panel de administracion web (puerto {p['port']})",
                "Confirma que este panel requiere autenticacion y que la "
                "contrasena por defecto del fabricante fue cambiada. Muchos "
                "ataques automatizados buscan credenciales por defecto en "
                "este tipo de interfaces."
            ))


def _check_smb(device, findings):
    """Regla 4: puertos 139/445 (SMB/NetBIOS) en dispositivos no claramente Windows."""
    smb_ports = {p["port"] for p in device.get("open_ports", [])}
    if 139 in smb_ports or 445 in smb_ports:
        findings.append(_finding(
            device, "media",
            "Servicio SMB/NetBIOS expuesto (puertos 139/445)",
            "SMB se usa para compartir archivos estilo Windows. Si este "
            "dispositivo no es una PC Windows donde lo necesites "
            "activamente, investiga por que esta expuesto y considera "
            "desactivarlo."
        ))


def _check_unidentified_fixed_mac(device, findings):
    """Regla 5: fabricante desconocido pero con MAC fija (de fabrica)."""
    if device.get("vendor") == "Desconocido" and device.get("mac_type") == "Fija de fabrica":
        findings.append(_finding(
            device, "informativa",
            "Dispositivo no identificado por fabricante",
            "La base de datos de fabricantes no reconoce este prefijo de "
            "MAC, aunque es una MAC real de fabrica (no aleatoria). "
            "Se recomienda identificar manualmente este dispositivo "
            "(por ejemplo, revisando que equipos tienes conectados "
            "fisicamente, o probando acceder a sus puertos abiertos)."
        ))


def _check_excessive_ports(device, findings):
    """Regla 6: mas de 3 puertos comunes abiertos simultaneamente."""
    open_ports = device.get("open_ports", [])
    if len(open_ports) > 3:
        port_list = ", ".join(str(p["port"]) for p in open_ports)
        findings.append(_finding(
            device, "media",
            f"Superficie de ataque amplia ({len(open_ports)} puertos abiertos)",
            f"Este dispositivo expone varios servicios a la vez (puertos: "
            f"{port_list}). Revisa cuales son realmente necesarios y "
            f"desactiva los que no uses activamente."
        ))


# Lista de todas las reglas a aplicar por cada dispositivo.
RULES = [
    _check_ssh,
    _check_telnet,
    _check_admin_panels,
    _check_smb,
    _check_unidentified_fixed_mac,
    _check_excessive_ports,
]


def analyze_devices(devices):
    """
    Aplica todas las reglas de hardening a la lista de dispositivos.
    Devuelve una lista de hallazgos (findings), ordenada por severidad
    (alta primero, informativa al final).
    """
    findings = []

    for device in devices:
        for rule in RULES:
            rule(device, findings)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    return findings


def print_findings(findings):
    """Imprime los hallazgos de forma legible en consola."""
    if not findings:
        print("\nNo se generaron recomendaciones de hardening. Buen estado general.\n")
        return

    print(f"\n=== Recomendaciones de hardening ({len(findings)} hallazgos) ===\n")

    for f in findings:
        print(f"[{f['severity'].upper()}] {f['title']}")
        print(f"   Dispositivo: {f['ip']} ({f['vendor']})")
        print(f"   Recomendacion: {f['recommendation']}\n")


"By: Slim2"