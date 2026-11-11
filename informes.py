
import json
import subprocess
import sys
import shutil

import pandas as pd
from io import BytesIO
from ipaddress import ip_address

from pathlib import Path

import streamlit as st

# Carpeta principal del proyecto
BASE = Path(__file__).resolve().parent

st.set_page_config(
    page_title="AI Security Copilot",
    page_icon="🛡️",
    layout="wide"
)

st.title("AI Security Copilot")
st.write("Sistema inteligente de análisis de incidentes de seguridad")

# Función para leer archivos JSON
def cargar_json(nombre):
    ruta = BASE / nombre

    if ruta.exists():
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)

    return []


# Función para ejecutar nuestros programas

def ejecutar(nombre, *argumentos, timeout=60):
    proceso = subprocess.run(
        [
            sys.executable,
            str(BASE / nombre),
            *[str(a) for a in argumentos]
        ],
        cwd=BASE,
        capture_output=True,
        text=True,
        timeout=timeout
    )

    if proceso.returncode != 0:
        raise RuntimeError(
            proceso.stderr.strip() or proceso.stdout.strip()
        )



# Cargar datos
alertas = cargar_json("alertas.json")
incidentes = cargar_json("incidentes.json")

# Panel de estadísticas
col1, col2, col3 = st.columns(3)


with col1:
    with st.container(border=True):
        st.metric(
            "Alertas detectadas",
            len(alertas)
        )

with col2:
    with st.container(border=True):
        st.metric(
            "Incidentes registrados",
            len(incidentes)
        )

with col3:
    with st.container(border=True):
        st.metric(
            "Incidentes de riesgo alto",
            sum(
                i["riesgo"] == "ALTO"
                for i in incidentes
            )
        )


st.divider()

# Botón para ejecutar el detector

# Subida y análisis de archivos CSV
st.subheader("Detección de amenazas")

archivo = st.file_uploader(
    "Sube un archivo CSV con registros de seguridad",
    type=["csv"]
)

st.caption(
    "Columnas necesarias: timestamp, ip, status. "
    "Si no subes un archivo, usaremos los datos de prueba."
)

if archivo is not None and archivo.size <= 2_000_000:
    try:
        vista = pd.read_csv(
            BytesIO(archivo.getvalue())
        )
        st.write("Vista previa:")
        st.dataframe(vista.head(10))
    except Exception:
        st.warning("No se puede previsualizar el CSV.")

if st.button("Analizar registros de seguridad"):
    try:
        if archivo is not None:
            if archivo.size > 2_000_000:
                raise ValueError("El CSV supera los 2 MB.")

            df = pd.read_csv(
                BytesIO(archivo.getvalue()),
                dtype=str,
                keep_default_na=False
            )

            df.columns = df.columns.str.strip()

            necesarias = {"timestamp", "ip", "status"}
            faltantes = necesarias - set(df.columns)

            if faltantes:
                raise ValueError(
                    f"Faltan columnas: {faltantes}"
                )

            df = df[["timestamp", "ip", "status"]].copy()

            if df.empty or (df == "").any().any():
                raise ValueError("Hay registros vacíos.")

            df["status"] = (
                df["status"].str.strip().str.upper()
            )

            if not df["status"].isin(
                ["SUCCESS", "FAIL"]
            ).all():
                raise ValueError(
                    "Los estados deben ser SUCCESS o FAIL."
                )

            df["ip"] = df["ip"].str.strip()

            for ip in df["ip"]:
                ip_address(ip)

            fechas = pd.to_datetime(
                df["timestamp"],
                errors="coerce",
                format="mixed"
            )

            if fechas.isna().any():
                raise ValueError("Hay fechas incorrectas.")

            df["timestamp"] = fechas.dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            
            ruta = BASE / "data" / "active_auth_logs.csv"
            df.to_csv(ruta, index=False)

        else:
            ruta = BASE / "data" / "active_auth_logs.csv"
            shutil.copyfile(
                BASE / "data" / "auth_logs.csv",
                ruta
            )

        ejecutar("detector.py", ruta)


        ejecutar("correlador.py")

        # Borrar informes de análisis anteriores
        (BASE / "informe.md").unlink(missing_ok=True)

        st.success("Análisis completado.")
        st.rerun()

    except Exception as e:
        st.error(f"Error durante el análisis: {e}")

# Mostrar incidentes

# Dashboard de incidentes
st.subheader("Panel de incidentes")

if incidentes:
    df_incidentes = pd.DataFrame(incidentes)

    col_izq, col_der = st.columns([2, 1])

    with col_izq:
        st.subheader("Incidentes detectados")

        # Filtro interactivo
        opciones = ["Todos"] + sorted(
            df_incidentes["riesgo"].unique().tolist()
        )

        filtro = st.selectbox(
            "Filtrar por nivel de riesgo",
            opciones
        )

        if filtro == "Todos":
            filtrados = df_incidentes
        else:
            filtrados = df_incidentes[
                df_incidentes["riesgo"] == filtro
            ]

        st.dataframe(
            filtrados,
            use_container_width=True,
            hide_index=True
        )

    with col_der:
        st.subheader("Distribución de riesgos")

        resumen = (
            df_incidentes.groupby("riesgo")
            .size()
            .reset_index(name="cantidad")
        )

        st.bar_chart(
            resumen,
            x="riesgo",
            y="cantidad"
        )

else:
    st.info("Todavía no hay incidentes registrados.")


# GRÁFICOS DE ACTIVIDAD DE RED

st.subheader("Análisis de actividad de red")

ruta_logs = BASE / "data" / "active_auth_logs.csv"

if ruta_logs.exists():

    logs = pd.read_csv(ruta_logs)

    logs["timestamp"] = pd.to_datetime(
        logs["timestamp"]
    )

    logs["ip"] = logs["ip"].astype(str)
    logs = logs.sort_values("timestamp")

    # Filtro por IP
    opciones_ip = ["Todas"] + sorted(
        logs["ip"].unique().tolist()
    )

    ip_seleccionada = st.selectbox(
        "Seleccionar dirección IP",
        opciones_ip
    )

    if ip_seleccionada != "Todas":
        logs_filtrados = logs[
            logs["ip"] == ip_seleccionada
        ]
    else:
        logs_filtrados = logs

    # Gráfico de intentos fallidos
    st.subheader("Intentos fallidos por IP")

    fallidos = logs_filtrados[
        logs_filtrados["status"] == "FAIL"
    ]

    if not fallidos.empty:
        conteo = (
            fallidos.groupby("ip")
            .size()
            .reset_index(name="fallos")
        )

        st.bar_chart(
            conteo,
            x="ip",
            y="fallos"
        )
    else:
        st.info("No hay intentos fallidos.")

    # Línea temporal
    st.subheader("Línea temporal de accesos")

    st.scatter_chart(
        logs_filtrados,
        x="timestamp",
        y="ip",
        color="status"
    )

    # Tabla de eventos
    with st.expander("Ver registros detallados"):
        st.dataframe(
            logs_filtrados,
            hide_index=True
        )

else:
    st.info("Analiza un CSV para visualizar la actividad.")

st.divider()

# Sección de inteligencia artificial
st.subheader("Análisis mediante IA")

if st.button("Generar informe con Ollama"):
    if not incidentes:
        st.warning("Primero debes detectar incidentes.")
    else:
        with st.spinner("Analizando incidentes..."):
            try:
                ejecutar("analizador_ia.py", timeout=240)
                st.success("Informe generado")
            except Exception as e:
                st.error(f"Error al generar el informe: {e}")

# Mostrar el informe
ruta_informe = BASE / "informe.md"

if ruta_informe.exists():
    st.markdown(ruta_informe.read_text(encoding="utf-8"))
else:
    st.info("Genera un informe para visualizarlo aquí.")
