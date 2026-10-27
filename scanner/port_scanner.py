"""
Modulo de escaneo de puertos.
Para cada dispositivo detectado, revisa que puertos comunes estan
abiertos, lo cual indica que servicios esta exponiendo en la red.
"""

import nmap


# Puertos comunes a revisar y su significado tipico.
# Empezamos con un set acotado (escaneo rapido) en vez de los 65535
# puertos posibles, para que no tarde horas por dispositivo.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet (inseguro, texto plano)",
    25: "SMTP",
    53: "DNS",
    80: "HTTP (interfaz web)",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS (interfaz web segura)",
    445: "SMB (compartir archivos Windows)",
    554: "RTSP (streaming, comun en camaras IP)",
    1900: "UPnP (comun en IoT)",
    3389: "RDP (escritorio remoto)",
    8080: "HTTP alternativo (paneles admin)",
    8443: "HTTPS alternativo",
}


def build_scanner():
    """Crea y devuelve el objeto escaner de nmap."""
    return nmap.PortScanner()


def scan_ports(scanner, ip_address):
    """
    Escanea los puertos comunes definidos en COMMON_PORTS para una IP dada.
    Devuelve una lista de diccionarios con puerto, servicio tipico y estado.
    """
    # Construimos el string de puertos para nmap, ej: "21,22,23,25,..."
    ports_str = ",".join(str(p) for p in COMMON_PORTS.keys())

    # -T4 = velocidad de escaneo mas agresiva (mas rapido, seguro en redes locales)
    # --open = solo nos interesa ver lo que esta abierto
    scanner.scan(ip_address, ports_str, arguments="-T4 --open")

    open_ports = []

    if ip_address in scanner.all_hosts():
        host_data = scanner[ip_address]

        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in ports:
                state = host_data[proto][port]["state"]
                if state == "open":
                    service_hint = COMMON_PORTS.get(port, "Desconocido")
                    open_ports.append({
                        "port": port,
                        "service_hint": service_hint,
                        "nmap_service": host_data[proto][port].get("name", "")
                    })

    return open_ports


def scan_all_devices(devices):
    """
    Recibe la lista de dispositivos (con 'ip', 'mac', 'vendor', etc.)
    y le agrega el campo 'open_ports' a cada uno con los resultados
    del escaneo de puertos.
    """
    scanner = build_scanner()

    for device in devices:
        print(f"  Escaneando puertos de {device['ip']}...")
        device["open_ports"] = scan_ports(scanner, device["ip"])

    return devices


if __name__ == "__main__":
    # Prueba rapida escaneando solo tu propia maquina (localhost)
    scanner = build_scanner()
    results = scan_ports(scanner, "127.0.0.1")

    print("\nPuertos abiertos en localhost:")
    for r in results:
        print(f"  Puerto {r['port']}: {r['service_hint']} (nmap: {r['nmap_service']})")

" By: Slim2"