
import json
import urllib.request
import urllib.error
from pathlib import Path

BASE = Path(__file__).resolve().parent

# Catálogo ampliable de hipótesis
CATALOGO = {
    "error_usuario": {
        "evento": "POSIBLE_FUERZA_BRUTA",
        "hipotesis": "Errores de contraseña de un usuario legítimo.",
        "comprobacion": "Verificar con el usuario los intentos de acceso."
    },
    "intentos_automatizados": {
        "evento": "POSIBLE_FUERZA_BRUTA",
        "hipotesis": "Posibles intentos automatizados de autenticación.",
        "comprobacion": "Revisar frecuencia, origen y cuentas afectadas."
    },
    "acceso_legitimo": {
        "evento": "ACCESO_SOSPECHOSO",
        "hipotesis": "Acceso legítimo después de varios fallos.",
        "comprobacion": "Comprobar usuario, dispositivo y autenticación MFA."
    },
    "acceso_no_autorizado": {
        "evento": "ACCESO_SOSPECHOSO",
        "hipotesis": "Posible acceso no autorizado, sin confirmar.",
        "comprobacion": "Revisar registros de sesión y actividad posterior."
    }
}

with open(BASE / "incidentes.json", encoding="utf-8") as f:
    incidentes = json.load(f)

with open(BASE / "alertas.json", encoding="utf-8") as f:
    alertas = json.load(f)

informe = "# Informe de AI Security Copilot\n\n"
informe += "*Análisis de registros simulados.*\n\n"

for incidente in incidentes:

    tipos = set(incidente["eventos"])

    # Python determina qué hipótesis son admisibles
    candidatos = {
        clave: valor
        for clave, valor in CATALOGO.items()
        if valor["evento"] in tipos
    }

    # Hechos registrados
    hechos = [
        f"- IP: {incidente['ip']}",
        f"- Riesgo asignado por reglas: {incidente['riesgo']}",
        f"- Inicio: {incidente['inicio']}",
        f"- Fin: {incidente['fin']}"
    ]

    for alerta in alertas:
        if alerta["ip"] != incidente["ip"]:
            continue

        if not (
            incidente["inicio"] <= alerta["fecha"] <= incidente["fin"]
        ):
            continue

        hechos.append(
            f"- {alerta['fecha']}: {alerta['tipo']}"
        )

    informe += f"## Incidente #{incidente['id']}\n\n"
    informe += "### Evidencias registradas\n\n"
    informe += "\n".join(hechos) + "\n\n"

    if not candidatos:
        informe += "Sin hipótesis disponibles para estos eventos.\n\n"
        continue

    # El LLM solo puede seleccionar identificadores
    prompt = f"""
Eres un analista SOC.

Evidencias:
{chr(10).join(hechos)}

Hipótesis disponibles:
{json.dumps(candidatos, ensure_ascii=False)}

Selecciona un máximo de 2 hipótesis que merezca
la pena investigar.

Si no hay información suficiente, devuelve
una lista vacía.

Responde únicamente con JSON:
{{"ids": ["identificador"]}}
"""

    datos = {
        "model": "llama3.2:1b",
        "prompt": prompt,
        "stream": False,
        "format": {
            "type": "object",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": list(candidatos)
                    },
                    "maxItems": 2
                }
            },
            "required": ["ids"],
            "additionalProperties": False
        },
        "options": {
            "num_gpu": 0,
            "temperature": 0
        }
    }

    peticion = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=json.dumps(datos).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    seleccion = []

    try:
        with urllib.request.urlopen(
            peticion, timeout=180
        ) as respuesta:
            resultado = json.load(respuesta)

        respuesta_ia = json.loads(resultado["response"])
        ids = respuesta_ia.get("ids", [])

        # VALIDACIÓN: rechazar identificadores no admitidos
        if isinstance(ids, list):
            for identificador in ids:
                if (
                    isinstance(identificador, str)
                    and identificador in candidatos
                    and identificador not in seleccion
                    and len(seleccion) < 2
                ):
                    seleccion.append(identificador)

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        KeyError
    ) as error:
        print("No se pudo validar la respuesta:", error)

    informe += "### Hipótesis seleccionadas por IA\n\n"

    if not seleccion:
        informe += "Ninguna hipótesis seleccionada o validada.\n\n"

    for identificador in seleccion:
        hipotesis = candidatos[identificador]

        informe += f"**{hipotesis['hipotesis']}**\n\n"
        informe += (
            f"- Comprobación: {hipotesis['comprobacion']}\n\n"
        )

    informe += (
        "**Nota:** Las hipótesis no confirman un ataque. "
        "Requieren investigación adicional.\n\n"
    )

with open(BASE / "informe.md", "w", encoding="utf-8") as f:
    f.write(informe)

print(informe)
print("\nInforme guardado en informe.md")
