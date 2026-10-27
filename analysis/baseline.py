"""
Modulo de linea base y deteccion de anomalias.

Guarda el resultado de un escaneo como "estado normal conocido" de la
red, y permite comparar escaneos futuros contra esa referencia para
detectar cambios: dispositivos nuevos, puertos nuevos abiertos, etc.
"""

import json
import os
from datetime import datetime


BASELINE_FILE = "analysis/baseline.json"


def save_baseline(devices, filepath=BASELINE_FILE):
    """
    Guarda la lista de dispositivos actual como la linea base.
    Se guarda junto con la fecha/hora en que se creo, para referencia.
    """
    data = {
        "created_at": datetime.now().isoformat(),
        "devices": devices
    }

    # Nos aseguramos de que la carpeta exista antes de escribir
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"Linea base guardada en {filepath} ({len(devices)} dispositivos)")


def load_baseline(filepath=BASELINE_FILE):
    """
    Carga la linea base guardada previamente.
    Devuelve None si no existe todavia (primera ejecucion).
    """
    if not os.path.exists(filepath):
        return None

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data


def _devices_by_mac(devices):
    """Convierte una lista de dispositivos en un diccionario indexado por MAC,
    para poder comparar facilmente dispositivo contra dispositivo."""
    return {d["mac"]: d for d in devices}


def compare_to_baseline(current_devices, filepath=BASELINE_FILE):
    """
    Compara el escaneo actual contra la linea base guardada.
    Devuelve un diccionario con:
      - new_devices: dispositivos que no estaban en la linea base
      - missing_devices: dispositivos de la linea base que ya no aparecen
      - new_ports: dict {mac: [puertos nuevos]} de dispositivos conocidos
                    que ahora exponen puertos que antes no tenian
    """
    baseline_data = load_baseline(filepath)

    if baseline_data is None:
        return None  # No hay linea base aun, no se puede comparar

    baseline_devices = _devices_by_mac(baseline_data["devices"])
    current_by_mac = _devices_by_mac(current_devices)

    baseline_macs = set(baseline_devices.keys())
    current_macs = set(current_by_mac.keys())

    new_devices = [current_by_mac[mac] for mac in (current_macs - baseline_macs)]
    missing_devices = [baseline_devices[mac] for mac in (baseline_macs - current_macs)]

    new_ports = {}
    # Para los dispositivos que existen en ambos escaneos, comparamos sus puertos
    for mac in (current_macs & baseline_macs):
        old_ports = set(p["port"] for p in baseline_devices[mac].get("open_ports", []))
        new_ports_set = set(p["port"] for p in current_by_mac[mac].get("open_ports", []))

        newly_opened = new_ports_set - old_ports
        if newly_opened:
            new_ports[mac] = {
                "ip": current_by_mac[mac]["ip"],
                "ports": sorted(newly_opened)
            }

    return {
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "new_ports": new_ports
    }


def print_comparison(comparison):
    """Imprime de forma legible el resultado de compare_to_baseline."""
    if comparison is None:
        print("\nNo hay linea base guardada todavia. Este escaneo se puede")
        print("guardar como la primera linea base con save_baseline().\n")
        return

    print("\n=== Comparacion contra la linea base ===")

    if comparison["new_devices"]:
        print(f"\n[ALERTA] {len(comparison['new_devices'])} dispositivo(s) NUEVO(S) detectado(s):")
        for d in comparison["new_devices"]:
            vendor = d.get("vendor", "Desconocido")
            print(f"   - {d['ip']} ({d['mac']}) - {vendor}")
    else:
        print("\nNo se detectaron dispositivos nuevos.")

    if comparison["missing_devices"]:
        print(f"\n[INFO] {len(comparison['missing_devices'])} dispositivo(s) de la linea base ya no estan activos:")
        for d in comparison["missing_devices"]:
            vendor = d.get("vendor", "Desconocido")
            print(f"   - {d['ip']} ({d['mac']}) - {vendor}")

    if comparison["new_ports"]:
        print(f"\n[ALERTA] Dispositivos conocidos con puertos NUEVOS abiertos:")
        for mac, info in comparison["new_ports"].items():
            print(f"   - {info['ip']} ({mac}): puertos nuevos {info['ports']}")
    else:
        print("\nNingun dispositivo conocido abrio puertos nuevos.")

    print()
