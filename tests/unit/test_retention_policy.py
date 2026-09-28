"""US042. Quien cargó el código puede soltarlo.

Dos decisiones distintas viven en la misma política y conviene no confundirlas:
el barrido automático, que se gobierna por una ventana de días, y el borrado
que alguien pide desde la pantalla. La segunda no puede esperar a la primera,
porque la pantalla promete «puedes soltarlo cuando quieras» y el servicio
respondía que faltaban veintitantos días.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.finding_validation.domain.services.retention_policy import (
    ExecutionRetentionState,
    RetentionOutcome,
    RetentionPolicy,
)

AHORA = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def estado(**cambios) -> ExecutionRetentionState:
    base = {
        "closed_at": AHORA - timedelta(days=2),
        "context_purged": False,
        "used_in_active_session": False,
    }
    base.update(cambios)
    return ExecutionRetentionState(**base)


class TestBorradoAPeticion:
    def test_borra_aunque_la_ejecucion_sea_de_ayer(self):
        """Es el caso corriente y el que estaba roto.

        Con la regla de la ventana, el botón de la pantalla solo servía para
        ejecuciones de hace más de un mes: en cualquier otra respondía que
        faltaban días, de modo que la historia no se podía ni demostrar.
        """
        decision = RetentionPolicy(30).decide_on_request(estado())
        assert decision.should_purge
        assert decision.outcome is RetentionOutcome.PURGE

    def test_una_ejecucion_sin_cerrar_tambien_se_puede_soltar(self):
        # El código ya está guardado desde que se recuperó: que la corrida siga
        # abierta no es motivo para retenerlo.
        assert RetentionPolicy(30).decide_on_request(estado(closed_at=None)).should_purge

    def test_no_repite_el_borrado(self):
        decision = RetentionPolicy(30).decide_on_request(estado(context_purged=True))
        assert not decision.should_purge
        assert decision.outcome is RetentionOutcome.ALREADY_PURGED

    def test_no_borra_por_debajo_de_una_sesion_en_curso(self):
        """Borrar el contexto de una ejecución en uso rompe esa sesión, y una
        sesión con una persona delante no se puede repetir."""
        decision = RetentionPolicy(30).decide_on_request(
            estado(used_in_active_session=True)
        )
        assert not decision.should_purge
        assert decision.outcome is RetentionOutcome.KEEP_IN_USE


class TestBarridoPorVentana:
    def test_conserva_dentro_de_la_ventana(self):
        decision = RetentionPolicy(30).decide(estado(), now=AHORA)
        assert not decision.should_purge
        assert "28 días" in decision.reason

    def test_purga_cumplida_la_ventana(self):
        decision = RetentionPolicy(30).decide(
            estado(closed_at=AHORA - timedelta(days=31)), now=AHORA
        )
        assert decision.should_purge

    @pytest.mark.parametrize("cerrada", [
        datetime(2026, 8, 1, 12, 0),                      # SQLite, sin zona
        datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),  # PostgreSQL, con ella
    ])
    def test_le_da_igual_que_la_fecha_traiga_zona_o_no(self, cerrada):
        """SQLite devuelve la fecha sin zona y PostgreSQL con ella.

        Compararla contra «ahora» reventaba con un 500 en la base local, que es
        justo donde se graba el video.
        """
        assert RetentionPolicy(30).decide(estado(closed_at=cerrada), now=AHORA).should_purge
