
import streamlit as st

pagina = st.navigation(
    [
        st.Page(
            "informes.py",
            title="Informes",
            icon=":material/analytics:",
            default=True
        ),
        st.Page(
            "agente.py",
            title="Agente",
            icon=":material/smart_toy:"
        )
    ],
    position="top"
)

pagina.run()
