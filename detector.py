
import json
import sys
from pathlib import Path
from collections import defaultdict, deque

import pandas as pd

UMBRAL = 3
VENTANA = pd.Timedelta(minutes=5)

UMBRAL_USUARIOS = 3
VENTANA_USUARIOS = pd.Timedelta(minutes=10)


def detectar_alertas(df):
    """Detecta patrones sospechosos de autenticación."""

    necesarias = {"timestamp", "ip", "status"}

    if not necesarias.issubset(df.columns):
        raise ValueError("Faltan columnas obligatorias")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["status"] = df["status"].str.strip().str.upper()
    df = df.sort_values("timestamp")

    tiene_usuario = "username" in df.columns

    if tiene_usuario:
        df["username"] = (
            df["username"].fillna("").astype(str).str.strip()
        )

    alertas = []

    for ip, registros in df.groupby("ip"):
        fallos_por_cuenta = defaultdict(deque)
        intentos_multicuenta = deque()
        alerta_multicuenta_activa = False

        for _, registro in registros.iterrows():
            momento = registro["timestamp"]
            estado = registro["status"]

            usuario = (
                registro["username"] if tiene_usuario else ""
            )

            # Si no existe columna username, usamos
            # el comportamiento original por IP.
            clave = (
                usuario if tiene_usuario else "__sin_usuario__"
            )

            if clave:
                fallos = fallos_por_cuenta[clave]

                while fallos and momento - fallos[0] > VENTANA:
                    fallos.popleft()

                if estado == "FAIL":
                    fallos.append(momento)

                    if len(fallos) == UMBRAL:
                        alerta = {
                            "ip": ip,
                            "tipo": "POSIBLE_FUERZA_BRUTA",
                            "fecha": str(momento),
                            "inicio_ventana": str(fallos[0]),
                            "intentos": len(fallos)
                        }

                        if tiene_usuario:
                            alerta["username"] = usuario

                        alertas.append(alerta)

                elif estado == "SUCCESS":
                    if len(fallos) >= UMBRAL:
                        alerta = {
                            "ip": ip,
                            "tipo": "ACCESO_SOSPECHOSO",
                            "fecha": str(momento),
                            "intentos_previos": len(fallos)
                        }

                        if tiene_usuario:
                            alerta["username"] = usuario

                        alertas.append(alerta)

                    fallos.clear()

            # Detección multicuenta: independiente
            # de los fallos contra una misma cuenta.
            if tiene_usuario:
                while (
                    intentos_multicuenta
                    and momento - intentos_multicuenta[0][0]
                    > VENTANA_USUARIOS
                ):
                    intentos_multicuenta.popleft()

                if estado == "FAIL" and usuario:
                    intentos_multicuenta.append(
                        (momento, usuario)
                    )

                usuarios = {
                    u for _, u in intentos_multicuenta
                }

                if (
                    len(usuarios) >= UMBRAL_USUARIOS
                    and not alerta_multicuenta_activa
                ):
                    alertas.append({
                        "ip": ip,
                        "tipo": "INTENTOS_MULTICUENTA",
                        "fecha": str(momento),
                        "inicio_ventana": str(
                            intentos_multicuenta[0][0]
                        ),
                        "usuarios_distintos": len(usuarios),
                        "usuarios": sorted(usuarios)
                    })

                alerta_multicuenta_activa = (
                    len(usuarios) >= UMBRAL_USUARIOS
                )

    return sorted(alertas, key=lambda a: a["fecha"])


if __name__ == "__main__":
    ruta = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path("data/auth_logs.csv")
    )

    df = pd.read_csv(ruta)
    alertas = detectar_alertas(df)

    Path("alertas.json").write_text(
        json.dumps(alertas, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"Total de alertas: {len(alertas)}")

    for alerta in alertas:
        print(
            f"{alerta['tipo']} - {alerta['ip']}"
        )
