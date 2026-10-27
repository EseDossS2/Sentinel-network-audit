"""
Modulo de identificacion de fabricante a partir de la direccion MAC.
Usa la base de datos OUI (Organizationally Unique Identifier) para
mapear el prefijo de cada MAC a su fabricante.
"""

from mac_vendor_lookup import MacLookup


def build_vendor_lookup():
    """
    Crea y devuelve un objeto MacLookup listo para usar.
    La primera vez que se ejecuta, descarga la base de datos OUI
    desde internet y la guarda localmente para usos futuros (no
    necesita internet las siguientes veces).
    """
    lookup = MacLookup()
    return lookup


def get_vendor(lookup, mac_address):
    """
    Devuelve el nombre del fabricante para una MAC dada.
    Si no se encuentra (MAC aleatoria, privada, o no registrada),
    devuelve "Desconocido".
    """
    try:
        return lookup.lookup(mac_address)
    except Exception:
        return "Desconocido"


def is_randomized_mac(mac_address):
    """
    Detecta si una MAC es "localmente administrada" (randomizada/privada)
    en vez de una MAC real de fabrica, revisando el bit U/L.

    Ese bit es el segundo bit del primer byte de la MAC. Si esta en 1,
    la MAC fue generada aleatoriamente (comun en celulares modernos
    por privacidad). Si esta en 0, es una MAC real asignada por el
    fabricante segun el estandar IEEE.
    """
    # Tomamos el primer bloque hexadecimal, ej "ae" de "ae:ee:0a:ba:a1:4a"
    first_octet_hex = mac_address.split(":")[0] if ":" in mac_address else mac_address[0:2]

    # Lo convertimos a numero entero para poder revisar sus bits
    first_octet_int = int(first_octet_hex, 16)

    # El bit U/L es el segundo bit menos significativo (posicion 1, valor 0x02)
    # Usamos una mascara AND para aislarlo: si el resultado no es 0, el bit esta activo
    is_local = (first_octet_int & 0b00000010) != 0

    return is_local


def enrich_devices(devices):
    """
    Recibe una lista de dispositivos (dicts con 'ip' y 'mac', tal como
    los devuelve discovery.scan_network) y le agrega los campos 'vendor'
    y 'mac_type' a cada uno.
    """
    lookup = build_vendor_lookup()

    for device in devices:
        device["vendor"] = get_vendor(lookup, device["mac"])

        if is_randomized_mac(device["mac"]):
            device["mac_type"] = "Aleatoria/Privada"
        else:
            device["mac_type"] = "Fija de fabrica"

    return devices


if __name__ == "__main__":
    # Prueba rapida del modulo de forma aislada
    test_devices = [
        {"ip": "192.168.1.1", "mac": "cc:d4:a1:ba:10:10"},
        {"ip": "192.168.1.8", "mac": "cc:28:aa:89:db:6a"},
    ]

    enriched = enrich_devices(test_devices)

    for d in enriched:
        print(f"{d['ip']:<18}{d['mac']:<20}{d['vendor']}")


" By: Slim2 "