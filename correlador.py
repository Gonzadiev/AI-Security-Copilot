
import json
import pandas as pd

VENTANA = pd.Timedelta(minutes=5)

# Leer las alertas generadas por el detector
with open("alertas.json", "r", encoding="utf-8") as f:
    alertas = json.load(f)

# Ordenarlas cronológicamente
alertas.sort(key=lambda a: a["fecha"])

incidentes = []
ultimo_por_ip = {}

for alerta in alertas:
    ip = alerta["ip"]
    momento = pd.to_datetime(alerta["fecha"])

    inicio_actividad = pd.to_datetime(
        alerta.get("inicio_ventana", alerta["fecha"])
    )


    # Buscar el último incidente de esta IP
    incidente = ultimo_por_ip.get(ip)

    # Crear otro incidente si han pasado más de 5 minutos
    if incidente is None or (
        momento - pd.to_datetime(incidente["fin"]) > VENTANA
    ):
        incidente = {
            "id": len(incidentes) + 1,
            "ip": ip,
            "riesgo": "MEDIO",
            "inicio": str(inicio_actividad),
            "fin": str(momento),
            "eventos": []
        }

        incidentes.append(incidente)
        ultimo_por_ip[ip] = incidente

    # Incorporar la alerta al incidente

    incidente["inicio"] = str(min(
        pd.to_datetime(incidente["inicio"]),
        inicio_actividad
    ))

    incidente["eventos"].append(alerta["tipo"])
    incidente["fin"] = str(momento)

    # Subir el riesgo si hubo acceso sospechoso
    if alerta["tipo"] == "ACCESO_SOSPECHOSO":
        incidente["riesgo"] = "ALTO"

# Guardar los incidentes
with open("incidentes.json", "w", encoding="utf-8") as f:
    json.dump(incidentes, f, indent=4, ensure_ascii=False)

# Mostrar resumen
for incidente in incidentes:
    print(f"INCIDENTE #{incidente['id']}")
    print(f"IP: {incidente['ip']}")
    print(f"RIESGO: {incidente['riesgo']}")
    print(f"ALERTAS: {len(incidente['eventos'])}")
    print("----------------------")
