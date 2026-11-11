
import pandas as pd
import sys
import json
from collections import deque

# Configuración
UMBRAL = 3
VENTANA = pd.Timedelta(minutes=5)

# Cargar y ordenar los registros
ruta_csv = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "data/auth_logs.csv"
)

df = pd.read_csv(ruta_csv)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp")

alertas = []

# Analizar los registros de cada IP
for ip, registros in df.groupby("ip"):
    fallos = deque()

    for _, registro in registros.iterrows():
        momento = registro["timestamp"]
        estado = registro["status"]

        # Eliminar fallos con más de 5 minutos
        while fallos and momento - fallos[0] > VENTANA:
            fallos.popleft()

        if estado == "FAIL":
            fallos.append(momento)

            
            if len(fallos) == UMBRAL:
                alertas.append({
                    "ip": ip,
                    "tipo": "POSIBLE_FUERZA_BRUTA",
                    "fecha": str(momento),
                    "inicio_ventana": str(fallos[0]),
                    "intentos": len(fallos)
                })


        elif estado == "SUCCESS":
            if len(fallos) >= UMBRAL:
                alertas.append({
                    "ip": ip,
                    "tipo": "ACCESO_SOSPECHOSO",
                    "fecha": str(momento),
                    "intentos_previos": len(fallos)
                })

            fallos.clear()

# Guardar las alertas en un JSON
with open("alertas.json", "w", encoding="utf-8") as archivo:
    json.dump(alertas, archivo, indent=4)

# Mostrar resultados
for alerta in alertas:
    print(f"ALERTA: {alerta['tipo']} - IP: {alerta['ip']}")

print(f"\nTotal de alertas: {len(alertas)}")
