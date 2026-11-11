
import unittest
from io import StringIO

import pandas as pd
from detector import detectar_alertas


def analizar(csv):
    df = pd.read_csv(StringIO(csv))
    return detectar_alertas(df)


class TestDeteccionAvanzada(unittest.TestCase):

    def test_fuerza_bruta_misma_cuenta(self):
        csv = """timestamp,ip,status,username
2026-11-11 10:00,10.0.0.5,FAIL,admin
2026-11-11 10:01,10.0.0.5,FAIL,admin
2026-11-11 10:02,10.0.0.5,FAIL,admin
2026-11-11 10:03,10.0.0.5,SUCCESS,admin
"""
        alertas = analizar(csv)

        self.assertEqual(
            [a["tipo"] for a in alertas],
            ["POSIBLE_FUERZA_BRUTA", "ACCESO_SOSPECHOSO"]
        )

    def test_acceso_a_otra_cuenta(self):
        csv = """timestamp,ip,status,username
2026-11-11 10:00,10.0.0.5,FAIL,admin
2026-11-11 10:01,10.0.0.5,FAIL,admin
2026-11-11 10:02,10.0.0.5,FAIL,admin
2026-11-11 10:03,10.0.0.5,SUCCESS,root
"""
        alertas = analizar(csv)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(
            alertas[0]["tipo"],
            "POSIBLE_FUERZA_BRUTA"
        )

    def test_multicuenta(self):
        csv = """timestamp,ip,status,username
2026-11-11 12:00,203.0.113.50,FAIL,admin
2026-11-11 12:04,203.0.113.50,FAIL,root
2026-11-11 12:08,203.0.113.50,FAIL,deploy
"""
        alertas = analizar(csv)

        self.assertEqual(len(alertas), 1)
        self.assertEqual(
            alertas[0]["tipo"],
            "INTENTOS_MULTICUENTA"
        )

    def test_compatibilidad_csv_antiguo(self):
        csv = """timestamp,ip,status
2026-11-11 10:00,10.0.0.5,FAIL
2026-11-11 10:01,10.0.0.5,FAIL
2026-11-11 10:02,10.0.0.5,FAIL
2026-11-11 10:03,10.0.0.5,SUCCESS
"""
        alertas = analizar(csv)

        self.assertEqual(len(alertas), 2)


if __name__ == "__main__":
    unittest.main()
