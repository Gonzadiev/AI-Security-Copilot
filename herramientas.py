
import csv
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent


def leer_json(nombre):
    ruta = BASE / nombre

    if not ruta.exists():
        return []

    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def consultar_incidentes():
    """Devuelve los incidentes detectados."""
    return leer_json("incidentes.json")


def investigar_ip(ip):
    """Consulta registros, alertas e incidentes de una IP."""

    ruta = BASE / "data" / "active_auth_logs.csv"

    if not ruta.exists():
        return {"error": "No hay registros analizados"}

    with open(ruta, encoding="utf-8-sig") as f:
        logs = list(csv.DictReader(f))

    registros = [r for r in logs if r["ip"] == ip]

    incidentes = [
        i for i in consultar_incidentes()
        if i["ip"] == ip
    ]

    alertas = [
        a for a in leer_json("alertas.json")
        if a["ip"] == ip
    ]

    return {
        "ip": ip,
        "intentos_fallidos": sum(
            r["status"] == "FAIL" for r in registros
        ),
        "accesos_exitosos": sum(
            r["status"] == "SUCCESS" for r in registros
        ),
        "incidentes": incidentes,
        "alertas": alertas,
        "registros": registros
    }


if __name__ == "__main__":
    for ip in ["10.0.0.5", "10.0.0.9"]:
        resultado = investigar_ip(ip)
        print(json.dumps(resultado, indent=2))
