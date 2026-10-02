# -*- coding: utf-8 -*-
"""El inventario del prompt declara lo que el codigo entregado trae.

Se escribe despues de encontrarlo corriendo el estudio. El recuperador pegaba
el cuerpo de los metodos llamados y el inventario no los nombraba, de modo que
el modelo leia «Llamadores incluidos: doGet», no veia mencion del llamado y
declaraba ausente un cuerpo que tenia delante. Once de los veinticuatro
hallazgos del lote salieron asi, ocho de ellos como «indeterminado».
"""
from uuid import uuid4

from src.finding_validation.domain.entities.code_context import CodeContext
from src.finding_validation.domain.entities.finding import Finding
from src.finding_validation.domain.value_objects.code_location import CodeLocation
from src.finding_validation.domain.value_objects.fingerprint import Fingerprint
from src.finding_validation.infrastructure.external.prompt_builder import (
    build_user_prompt,
    line_ranges,
    system_prompt,
)


def _hallazgo() -> Finding:
    return Finding(
        rule_id="java.lang.security.audit.xss.no-direct-response-writer",
        severity="warning",
        location=CodeLocation(
            file_path="BenchmarkTest02045.java", start_line=59, end_line=59
        ),
        fingerprint=Fingerprint.compute(
            "java.lang.security.audit.xss", "BenchmarkTest02045.java", "cuerpo"
        ),
        cwe="CWE-79",
    )


def _contexto(**extra) -> CodeContext:
    base = {
        "finding_id": uuid4(),
        "enclosing_function": "doPost",
        "text": "53:         String bar = doSomething(request, param);\n"
                "63:     private static String doSomething(...)\n"
                "71:         else bar = param;",
        "available_lines": frozenset({53, 63, 71}),
        "callers": ("doGet",),
        "callees": ("doSomething",),
    }
    base.update(extra)
    return CodeContext(**base)


class TestElInventarioNombraLosLlamados:
    def test_el_llamado_aparece_en_el_inventario(self):
        texto = build_user_prompt(_hallazgo(), _contexto())
        cabecera = texto.split("CÓDIGO")[0]
        assert "doSomething" in cabecera

    def test_se_dice_que_viene_con_su_cuerpo(self):
        """Nombrarlo sin más dejaría en pie la duda de si vino el cuerpo."""
        texto = build_user_prompt(_hallazgo(), _contexto())
        assert "Llamados incluidos, con su cuerpo entero: doSomething" in texto

    def test_sin_llamados_lo_dice_y_no_calla(self):
        texto = build_user_prompt(_hallazgo(), _contexto(callees=()))
        assert "Llamados incluidos, con su cuerpo entero: ninguno" in texto

    def test_el_llamador_sigue_declarandose(self):
        texto = build_user_prompt(_hallazgo(), _contexto())
        assert "Llamadores incluidos: doGet" in texto

    def test_la_regla_cierra_el_paso_a_la_ausencia_inventada(self):
        assert "Llamados incluidos" in system_prompt()


class TestLasLineasDisponiblesNoSeAnuncianPorSusExtremos:
    def test_los_huecos_no_se_prometen(self):
        """«32 a 74» prometia la 37 y la 62, que eran lineas en blanco."""
        disponibles = (
            list(range(32, 37)) + list(range(38, 62)) + list(range(63, 75))
        )
        assert line_ranges(disponibles) == "32-36, 38-61, 63-74"

    def test_una_linea_sola_no_se_escribe_como_tramo(self):
        assert line_ranges([5]) == "5"

    def test_tramos_sueltos(self):
        assert line_ranges([5, 9, 10, 11, 20]) == "5, 9-11, 20"

    def test_sin_lineas(self):
        assert line_ranges([]) == "ninguna"

    def test_el_prompt_lleva_los_tramos_y_no_el_rango(self):
        texto = build_user_prompt(
            _hallazgo(), _contexto(available_lines=frozenset({53, 63, 71}))
        )
        assert "Líneas disponibles: 53, 63, 71" in texto


class TestLaVersionCambiaConLaConsulta:
    def test_la_etiqueta_subio_a_v2(self):
        """Tocar la consulta sin cambiar la version invalidaria la comparacion."""
        from src.finding_validation.infrastructure.external.prompt_builder import (
            CURRENT_VERSION,
        )

        assert CURRENT_VERSION.label == "v2"
