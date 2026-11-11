import json
import re
import urllib.request

from herramientas import consultar_incidentes, investigar_ip

MODELO = "llama3.2:1b"
PRIORIDAD = {"BAJO": 1, "MEDIO": 2, "ALTO": 3, "CRITICO": 4}

# Recomendaciones escritas y revisadas por nosotros.
RECOMENDACIONES = {
    "identidad": ("Confirmar con el usuario si reconoce los intentos.", {"POSIBLE_FUERZA_BRUTA"}),
    "origen": ("Revisar la procedencia y el horario de los accesos.", {"POSIBLE_FUERZA_BRUTA", "ACCESO_SOSPECHOSO"}),
    "sesion": ("Revisar la sesión iniciada y la actividad posterior.", {"ACCESO_SOSPECHOSO"}),
    "mfa": ("Comprobar si se exigió y superó la autenticación multifactor.", {"ACCESO_SOSPECHOSO"}),
}


def obtener_evidencias(pregunta):
    incidentes = consultar_incidentes()
    ips = list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", pregunta)))
    if not ips:
        ips = sorted({i["ip"] for i in incidentes})

    detalles = [investigar_ip(ip) for ip in ips]
    lineas = [f"**Incidentes registrados en total:** {len(incidentes)}"]
    riesgos = []

    for d in detalles:
        if "error" in d:
            lineas.append(f"- No se pudieron consultar los datos de `{d.get('ip', 'una IP')}`.")
            continue
        lineas.append(
            f"- **{d['ip']}**: {d['intentos_fallidos']} fallos, "
            f"{d['accesos_exitosos']} accesos exitosos."
        )
        if not d["incidentes"]:
            lineas.append("  - No tiene incidentes registrados.")
        for i in d["incidentes"]:
            eventos = i["eventos"]
            motivo = (
                "fallos seguidos de acceso exitoso"
                if "ACCESO_SOSPECHOSO" in eventos
                else "múltiples fallos de autenticación"
            )
            lineas.append(
                f"  - Incidente #{i['id']}: riesgo **{i['riesgo']}**, "
                f"{i['inicio']} a {i['fin']}. "
                f"Motivo observado: {motivo}."
            )
            riesgos.append((PRIORIDAD.get(i["riesgo"], 0), d["ip"], i["riesgo"]))

    if riesgos:
        mayor = max(nivel for nivel, _, _ in riesgos)
        superiores = sorted({(ip, riesgo) for nivel, ip, riesgo in riesgos if nivel == mayor})
        lineas.append(
            "**Mayor prioridad según nuestras reglas:** " +
            ", ".join(f"`{ip}` ({riesgo})" for ip, riesgo in superiores) + "."
        )

    return "\n\n".join(lineas), detalles


def sugerir_comprobaciones(pregunta, detalles):
    tipos = {
        evento
        for d in detalles if "error" not in d
        for incidente in d["incidentes"]
        for evento in incidente["eventos"]
    }
    opciones = {
        clave: texto
        for clave, (texto, eventos) in RECOMENDACIONES.items()
        if tipos & eventos
    }
    if not opciones:
        return [], "No hay comprobaciones disponibles para esos eventos."

    esquema = {
        "type": "object",
        "properties": {
            "ids": {
                "type": "array",
                "items": {"type": "string", "enum": list(opciones)},
                "maxItems": 3,
            }
        },
        "required": ["ids"],
        "additionalProperties": False,
    }
    solicitud = {
        "model": MODELO,
        "stream": False,
        "format": esquema,
        "messages": [
            {"role": "system", "content": (
                "Eres un asistente SOC. Selecciona hasta tres comprobaciones "
                "útiles de la lista. No redactes hechos ni crees opciones. "
                "Devuelve solo JSON con la clave ids."
            )},
            {"role": "user", "content": json.dumps({
                "pregunta": pregunta,
                "incidentes": [d.get("incidentes", []) for d in detalles],
                "comprobaciones_permitidas": opciones,
            }, ensure_ascii=False)},
        ],
        "options": {"num_gpu": 0, "temperature": 0, "num_predict": 100},
    }
    peticion = urllib.request.Request(
        "http://localhost:11434/api/chat",
        data=json.dumps(solicitud).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(peticion, timeout=180) as respuesta:
            contenido = json.load(respuesta)["message"]["content"]
        seleccion = json.loads(contenido)["ids"]
        if not isinstance(seleccion, list):
            raise ValueError("Formato de respuesta incorrecto")
        validas = list(dict.fromkeys(
            clave for clave in seleccion if isinstance(clave, str) and clave in opciones
        ))[:3]
        return [opciones[clave] for clave in validas], ""
    except (OSError, TimeoutError, ValueError, KeyError, TypeError) as error:
        return [], f"Ollama no devolvió una selección válida: {error}"


def responder(pregunta):
    hechos, detalles = obtener_evidencias(pregunta)
    sugerencias, aviso = sugerir_comprobaciones(pregunta, detalles)
    return {"hechos": hechos, "sugerencias": sugerencias,
            "aviso": aviso, "evidencias": detalles}
