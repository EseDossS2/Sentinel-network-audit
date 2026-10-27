# Sentinel — Sistema de Auditoría y Hardening de Redes Domésticas

**Autor:** SLIM2

## Descripción

Sentinel es una herramienta de auditoría de seguridad para redes domésticas/PYMEs, desarrollada en Python. Combina descubrimiento de dispositivos, identificación de fabricantes, escaneo de puertos, detección de anomalías mediante línea base y generación automática de recomendaciones de hardening — todo consolidado en un informe HTML profesional.

El proyecto nace de un enfoque práctico: en vez de construir una herramienta genérica de laboratorio, se diseñó y probó iterativamente sobre una red doméstica real, lo que permitió validar cada módulo contra datos genuinos y casos reales de identificación de dispositivos.

## Arquitectura

El proyecto está organizado en 5 módulos independientes que se integran en un flujo único (`scanner/discovery.py`):

```
proyecto-sentinel/
├── scanner/
│   ├── discovery.py       # Orquestador principal + descubrimiento ARP
│   ├── vendor_lookup.py   # Identificación de fabricante y tipo de MAC
│   └── port_scanner.py    # Escaneo de puertos comunes (nmap)
├── analysis/
│   └── baseline.py        # Línea base y detección de anomalías
├── hardening/
│   └── hardening_rules.py # Motor de reglas de recomendaciones de seguridad
├── reports/
│   └── report_generator.py # Generación de informes HTML
└── docs/
    └── README.md           # Este documento
```

**Flujo de ejecución:**
1. `discovery.py` escanea la red local vía ARP y obtiene IP + MAC de cada dispositivo activo.
2. `vendor_lookup.py` enriquece cada dispositivo con su fabricante (base de datos OUI) y determina si su MAC es aleatoria/privada (bit U/L) o fija de fábrica.
3. `port_scanner.py` escanea 16 puertos comunes por dispositivo para detectar servicios expuestos.
4. `baseline.py` compara el escaneo actual contra un estado de referencia guardado (`analysis/baseline.json`), señalando dispositivos nuevos, ausentes, o puertos recién abiertos.
5. `hardening_rules.py` aplica un conjunto de reglas sobre los hallazgos y genera recomendaciones clasificadas por severidad (alta/media/baja/informativa).
6. `report_generator.py` consolida todo en un informe HTML con resumen, tabla de dispositivos, comparación y recomendaciones.

## Instalación y uso

### Requisitos
- Python 3.11+
- Nmap instalado en el sistema
- Permisos de administrador (necesarios para el escaneo ARP)

### Instalación
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1     # Windows
pip install scapy python-nmap mac-vendor-lookup flask pandas
```

### Ejecución
```bash
python scanner/discovery.py
```

La primera ejecución crea automáticamente la línea base (`analysis/baseline.json`). Las ejecuciones siguientes comparan contra ella y reportan diferencias.

Para aceptar el estado actual como la nueva línea base (después de revisar y confirmar que los cambios son legítimos):
```bash
python scanner/discovery.py --update-baseline
```

Cada ejecución genera un nuevo informe en `reports/reporte_<fecha>_<hora>.html`.

## Metodología

### Detección de MAC aleatoria
En vez de depender únicamente de bases de datos de fabricantes (que pueden estar desactualizadas), el sistema analiza directamente el bit "localmente administrado" (U/L) del primer byte de cada MAC, siguiendo el estándar IEEE 802. Esto permite distinguir con certeza técnica entre una MAC real de fábrica y una generada aleatoriamente por privacidad (común en celulares y Smart TVs modernos).

### Gestión de línea base
El sistema nunca sobrescribe automáticamente la línea base tras la primera ejecución. Esta es una decisión de diseño deliberada: actualizar la referencia de "normalidad" debe ser siempre una decisión humana consciente, tras investigar cada alerta — nunca un proceso automático. Esto evita tanto la fatiga de alertas (alertar repetidamente sobre algo ya confirmado como legítimo) como la normalización silenciosa de cambios no revisados.

### Motor de reglas de hardening
Las 6 reglas implementadas no son una lista genérica copiada de buenas prácticas generales, sino que fueron diseñadas a partir de hallazgos reales obtenidos durante el desarrollo (puerto SSH expuesto en el router, paneles de administración en dispositivos IPTV, un dispositivo IoT no identificable por fabricante, etc.).

## Caso de estudio: hallazgos en red real

Durante el desarrollo, el sistema se probó contra una red doméstica real, permitiendo identificar:
- Un router con SSH expuesto, correctamente mitigado tras confirmar que el acceso WAN estaba deshabilitado (el puerto permanece abierto solo en LAN, comportamiento esperado).
- Dos dispositivos del fabricante Commscope (probables decodificadores IPTV) con paneles de administración en el puerto 8080.
- Un dispositivo IoT (fabricante GSD Vietnam Technology) con un servicio en el puerto 8443 que rechaza conexiones genéricas (`tcpwrapped`), consistente con un servicio de administración restringido a su app oficial.
- Identificación de una Smart TV mediante correlación de eventos: se comparó el estado de la red con el dispositivo encendido y apagado, confirmando su MAC aleatoria por eliminación de variables.

## Aprendizajes y limitaciones

Este proyecto se desarrolló como parte de un proceso de aprendizaje activo, por lo que es transparente sobre su alcance:

- Escanea únicamente 16 puertos comunes, no el rango completo de 65535 — prioriza velocidad sobre cobertura exhaustiva.
- No realiza detección de vulnerabilidades específicas (CVEs); identifica servicios expuestos, no fallas conocidas de esos servicios.
- La identificación de fabricante depende de una base de datos OUI que puede no estar siempre actualizada.
- No automatiza la aplicación de las recomendaciones de hardening (por diseño: cambios de configuración de red deberían ser decisiones humanas revisadas).

## Próximos pasos posibles

- Ampliar el rango de puertos escaneados con un modo "profundo" opcional.
- Integrar una base de datos de vulnerabilidades conocidas (CVE) por servicio/versión detectada.
- Agregar un dashboard web interactivo (Flask) en vez de solo informes HTML estáticos.
- Programar el escaneo periódico automático con notificaciones (ej. correo) ante alertas de severidad alta.

---
*Proyecto desarrollado por SLIM2 como evidencia de prácticas profesionales en ingeniería de software, con énfasis en ciberseguridad aplicada.*
