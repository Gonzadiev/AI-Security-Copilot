"""Pruebas de AI Security Copilot. Ejecutar: python -m unittest -v test_proyecto.py"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import herramientas
import motor_agente

ORIGEN = Path(__file__).resolve().parent


class TestSecurityCopilot(unittest.TestCase):
    def setUp(self):
        temporal = tempfile.TemporaryDirectory()
        self.addCleanup(temporal.cleanup)
        self.carpeta = Path(temporal.name)
        (self.carpeta / "data").mkdir()
        for nombre in ("detector.py", "correlador.py"):
            shutil.copy2(ORIGEN / nombre, self.carpeta / nombre)

    def ejecutar(self, programa, *args, comprobar=True):
        resultado = subprocess.run(
            [sys.executable, str(self.carpeta / programa), *map(str, args)],
            cwd=self.carpeta,
            text=True,
            capture_output=True,
            timeout=30,
        )
        if comprobar and resultado.returncode != 0:
            self.fail(f"Fallo en {programa}:\n{resultado.stderr}")
        return resultado

    def analizar(self, contenido):
        ruta = self.carpeta / "data" / "active_auth_logs.csv"
        ruta.write_text(contenido.strip() + "\n", encoding="utf-8")
        self.ejecutar("detector.py", ruta)
        self.ejecutar("correlador.py")
        alertas = json.loads((self.carpeta / "alertas.json").read_text(encoding="utf-8"))
        incidentes = json.loads((self.carpeta / "incidentes.json").read_text(encoding="utf-8"))
        return alertas, incidentes

    def datos_ejemplo(self):
        return """timestamp,ip,status
2026-11-11 10:00,192.168.1.10,SUCCESS
2026-11-11 10:01,10.0.0.5,FAIL
2026-11-11 10:02,10.0.0.5,FAIL
2026-11-11 10:03,10.0.0.5,FAIL
2026-11-11 10:05,10.0.0.5,SUCCESS
2026-11-11 11:00,10.0.0.9,FAIL
2026-11-11 11:01,10.0.0.9,FAIL
2026-11-11 11:02,10.0.0.9,FAIL"""

    def test_dos_incidentes_y_horas_correctas(self):
        alertas, incidentes = self.analizar(self.datos_ejemplo())
        self.assertEqual(len(alertas), 3)
        self.assertEqual(len(incidentes), 2)
        por_ip = {i["ip"]: i for i in incidentes}
        self.assertEqual(por_ip["10.0.0.5"]["riesgo"], "ALTO")
        self.assertEqual(por_ip["10.0.0.5"]["inicio"], "2026-11-11 10:01:00")
        self.assertEqual(por_ip["10.0.0.9"]["riesgo"], "MEDIO")
        self.assertEqual(por_ip["10.0.0.9"]["inicio"], "2026-11-11 11:00:00")

    def test_registros_normales_sin_alertas(self):
        alertas, incidentes = self.analizar("""timestamp,ip,status
2026-11-11 10:00,192.168.1.10,SUCCESS
2026-11-11 10:02,192.168.1.11,FAIL""")
        self.assertEqual(alertas, [])
        self.assertEqual(incidentes, [])

    def test_fallos_espaciados_no_generan_alerta(self):
        alertas, incidentes = self.analizar("""timestamp,ip,status
2026-11-11 10:00,10.0.0.5,FAIL
2026-11-11 10:06,10.0.0.5,FAIL
2026-11-11 10:12,10.0.0.5,FAIL""")
        self.assertEqual(alertas, [])
        self.assertEqual(incidentes, [])

    def test_csv_sin_columna_obligatoria_se_rechaza(self):
        ruta = self.carpeta / "data" / "active_auth_logs.csv"
        ruta.write_text("timestamp,ip\n2026-11-11 10:00,10.0.0.5\n", encoding="utf-8")
        resultado = self.ejecutar("detector.py", ruta, comprobar=False)
        self.assertNotEqual(resultado.returncode, 0)

    def test_consulta_ip_inexistente(self):
        self.analizar(self.datos_ejemplo())
        with patch.object(herramientas, "BASE", self.carpeta):
            resultado = herramientas.investigar_ip("10.0.0.123")
        self.assertEqual(resultado["intentos_fallidos"], 0)
        self.assertEqual(resultado["accesos_exitosos"], 0)
        self.assertEqual(resultado["incidentes"], [])
        self.assertEqual(resultado["registros"], [])

    def test_ollama_desconectado_conserva_los_hechos(self):
        self.analizar(self.datos_ejemplo())
        with patch.object(herramientas, "BASE", self.carpeta):
            with patch(
                "motor_agente.urllib.request.urlopen",
                side_effect=urllib.error.URLError("Ollama desconectado"),
            ):
                respuesta = motor_agente.responder("Compara 10.0.0.5 y 10.0.0.9")
        self.assertIn("10.0.0.5", respuesta["hechos"])
        self.assertIn("10.0.0.9", respuesta["hechos"])
        self.assertEqual(respuesta["sugerencias"], [])
        self.assertTrue(respuesta["aviso"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
