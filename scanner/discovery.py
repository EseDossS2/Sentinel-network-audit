"""
Modulo de descubrimiento de dispositivos en la red local.
Usa un ARP scan para detectar que dispositivos estan activos,
obteniendo su IP y direccion MAC.
"""

from scapy.all import ARP, Ether, srp
import sys
import os

# Le decimos a Python explicitamente donde buscar nuestros propios modulos,
# ya que estan repartidos en distintas carpetas (scanner/, analysis/).
# Esto evita problemas segun como se ejecute el script.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)                              # raiz del proyecto
sys.path.insert(0, os.path.join(PROJECT_ROOT, "analysis"))    # carpeta analysis/
sys.path.insert(0, os.path.join(PROJECT_ROOT, "reports"))     # carpeta reports/
sys.path.insert(0, os.path.join(PROJECT_ROOT, "hardening"))   # carpeta hardening/

from vendor_lookup import enrich_devices
from port_scanner import scan_all_devices
from baseline import load_baseline, save_baseline, compare_to_baseline, print_comparison
from report_generator import generate_report
from hardening_rules import analyze_devices, print_findings


def print_banner():
    """Muestra el banner ASCII de bienvenida al iniciar el programa."""
    banner = r"""
 ____  _____ _   _ _____ ___ _   _ _____ _
/ ___|| ____| \ | |_   _|_ _| \ | | ____| |
\___ \|  _| |  \| | | |  | ||  \| |  _| | |
 ___) | |___| |\  | | |  | || |\  | |___| |___
|____/|_____|_| \_| |_| |___|_| \_|_____|_____|

           Auditoria y Hardening de Redes
                  BY: SLIM2
    """
    print(banner)


def scan_network(target_ip_range):
    """
    Escanea un rango de IPs en la red local usando ARP.

    target_ip_range: ej. "192.168.1.1/24" (toda la subred)
    Devuelve una lista de diccionarios con ip y mac de cada dispositivo activo.
    """

    # Creamos el paquete ARP: "quien tiene esta IP?"
    arp_request = ARP(pdst=target_ip_range)

    # Lo envolvemos en un frame Ethernet dirigido a todos (broadcast)
    # ff:ff:ff:ff:ff:ff es la direccion MAC de broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combinamos ambos: el paquete final que se envia a la red
    packet = broadcast / arp_request

    # srp() envia el paquete y espera respuestas (timeout en segundos)
    # Devuelve dos listas: respuestas recibidas (answered) y no recibidas (unanswered)
    answered, unanswered = srp(packet, timeout=3, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,   # IP de origen de la respuesta
            "mac": received.hwsrc  # MAC de origen de la respuesta
        })

    return devices


def print_results(devices):
    print("\n--- Dispositivos encontrados en la red ---")
    print(f"{'IP':<18}{'MAC':<20}{'Fabricante':<30}{'Tipo de MAC'}")
    print("-" * 95)
    for device in devices:
        vendor = device.get('vendor', '')
        mac_type = device.get('mac_type', '')
        print(f"{device['ip']:<18}{device['mac']:<20}{vendor:<30}{mac_type}")

        open_ports = device.get('open_ports', [])
        if open_ports:
            for p in open_ports:
                print(f"      -> Puerto {p['port']} abierto: {p['service_hint']}")
        else:
            print(f"      -> Sin puertos comunes abiertos (o no se pudo escanear)")

    print(f"\nTotal: {len(devices)} dispositivos activos\n")


if __name__ == "__main__":
    # IMPORTANTE: cambia este rango por el de tu propia red.
    # Para saber tu rango: ejecuta "ipconfig" en otra terminal,
    # busca "Puerta de enlace predeterminada" (ej. 192.168.1.1)
    # y usa esa misma base con /24, ej: "192.168.1.1/24"
    target = "192.168.1.1/24"

    print_banner()

    print(f"Escaneando red: {target} ...")
    print("(Esto puede tardar unos segundos)")

    try:
        found_devices = scan_network(target)
        print("Identificando fabricantes...")
        found_devices = enrich_devices(found_devices)

        print("Escaneando puertos (esto puede tardar uno o dos minutos)...")
        found_devices = scan_all_devices(found_devices)

        print_results(found_devices)

        # Revisamos si el usuario paso el flag --update-baseline al ejecutar
        # el script, ej: python scanner/discovery.py --update-baseline
        force_update = "--update-baseline" in sys.argv

        existing_baseline = load_baseline()

        comparison = None

        if existing_baseline is None:
            # Primera vez: no hay nada contra que comparar, asi que
            # este mismo escaneo se convierte en la linea base.
            save_baseline(found_devices)
        elif force_update:
            # El usuario reviso los cambios y decidio aceptarlos como
            # el nuevo estado "normal" de la red.
            print("\n[INFO] Flag --update-baseline detectado: actualizando linea base con el estado actual.")
            save_baseline(found_devices)
        else:
            comparison = compare_to_baseline(found_devices)
            print_comparison(comparison)

        findings = analyze_devices(found_devices)
        print_findings(findings)

        generate_report(found_devices, comparison=comparison, network_range=target,
                         findings=findings)
    except PermissionError:
        print("\nERROR: Este script necesita permisos de administrador.")
        print("En Windows: abre PowerShell como Administrador y vuelve a intentar.")
        sys.exit(1)
