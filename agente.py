import streamlit as st
from motor_agente import responder

st.set_page_config(page_title="Agente | AI Security Copilot", layout="wide")
st.title("Agente de Seguridad")
st.caption("Consultas verificables con Python + comprobaciones sugeridas por Ollama")

if "historial_agente_v2" not in st.session_state:
    st.session_state.historial_agente_v2 = []

if st.button("Limpiar conversación"):
    st.session_state.historial_agente_v2 = []
    st.rerun()


def mostrar_mensaje(m):
    with st.chat_message(m["rol"]):
        if m["rol"] == "user":
            st.markdown(m["texto"])
        else:
            st.markdown("#### Hechos obtenidos con Python")
            st.markdown(m["hechos"])
            st.markdown("#### Comprobaciones sugeridas por IA")
            if m["sugerencias"]:
                for s in m["sugerencias"]:
                    st.markdown(f"- {s}")
            else:
                st.info("Sin sugerencias disponibles.")
            if m["aviso"]:
                st.caption(m["aviso"])
            with st.expander("Ver evidencias consultadas"):
                st.json(m["evidencias"])


for mensaje in st.session_state.historial_agente_v2:
    mostrar_mensaje(mensaje)

pregunta = st.chat_input("Pregunta sobre las IP o los incidentes...")
if pregunta:
    usuario = {"rol": "user", "texto": pregunta}
    st.session_state.historial_agente_v2.append(usuario)
    mostrar_mensaje(usuario)

    with st.spinner("Consultando registros y Ollama..."):
        try:
            resultado = responder(pregunta)
            asistente = {"rol": "assistant", **resultado}
            st.session_state.historial_agente_v2.append(asistente)
            mostrar_mensaje(asistente)
        except Exception as error:
            st.error(f"Error al consultar los datos: {error}")
