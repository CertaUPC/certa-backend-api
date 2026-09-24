"""Credenciales acotadas: acuñado, verificación y lo que NO autorizan.

Lo que esta suite protege no es que la credencial funcione, que es lo fácil de
ver, sino que no funcione donde no debe. Una credencial de participación que
pasara una comprobación de rol abriría la lista de participantes y las
ejecuciones de todos, y ese fallo no se nota usando el sistema: se nota cuando
alguien lo busca.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.iam.domain.access_grant import (
    AccessGrant,
    GrantKind,
    InvalidGrant,
    acunar,
    leer,
)
from src.iam.infrastructure.persistence.grant_repository import (
    SqlAccessGrantRepository,
)
from src.iam.interfaces.rest.dependencies import CurrentUser
from src.shared.database import Base

# Registra las tablas del esquema completo: access_grants referencia a users.
import src.iam.infrastructure.persistence.models  # noqa: F401
import src.shared.database_experiment  # noqa: F401


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


class TestAcunado:
    def test_el_token_lleva_dentro_a_que_fila_ir(self):
        """Verificar es una búsqueda indexada y una comparación.

        Sin el identificador dentro, comprobar un token obligaría a recorrer la
        tabla entera cifrando fila por fila.
        """
        grant, token = acunar(GrantKind.WORKER, "proyecto-1")
        tipo, identificador, secreto = leer(token)
        assert tipo is GrantKind.WORKER
        assert identificador == grant.id
        assert grant.coincide(secreto)

    def test_el_secreto_no_queda_en_la_entidad(self):
        grant, token = acunar(GrantKind.PARTICIPATION, "p-1")
        _, _, secreto = leer(token)
        # Ni el secreto ni el token entero aparecen en lo que se persiste.
        assert secreto not in repr(grant)
        assert token not in repr(grant)
        assert len(grant.secret_hash) == 64

    def test_el_secreto_de_otra_credencial_no_casa(self):
        """Dos credenciales del mismo sujeto no se sirven la una a la otra."""
        grant, _ = acunar(GrantKind.WORKER, "proyecto-1")
        otro, token_del_otro = acunar(GrantKind.WORKER, "proyecto-1")
        _, _, secreto_del_otro = leer(token_del_otro)

        assert otro.coincide(secreto_del_otro)
        assert not grant.coincide(secreto_del_otro)
        assert not grant.coincide("0" * 64)

    @pytest.mark.parametrize(
        "malo",
        ["", "   ", "certa", "certa_wk_1", "otro_wk_1_2", "certa_zz_1_2",
         "certa_wk__secreto"],
    )
    def test_un_token_deforme_se_rechaza(self, malo):
        with pytest.raises(InvalidGrant):
            leer(malo)

    def test_la_vigencia_depende_del_tipo(self):
        """La del trabajador se instala una vez; la de participación cubre una
        sesión y no tiene por qué servir al día siguiente."""
        w, _ = acunar(GrantKind.WORKER, "proyecto-1")
        p, _ = acunar(GrantKind.PARTICIPATION, "p-1")
        assert w.expires_at > p.expires_at

    def test_se_puede_emitir_sin_vencimiento_a_proposito(self):
        g, _ = acunar(GrantKind.WORKER, "proyecto-1", vigencia=None)
        assert g.expires_at is None
        assert g.is_active


class TestVigencia:
    def test_revocar_marca_y_no_borra(self):
        g, _ = acunar(GrantKind.WORKER, "proyecto-1")
        g.revocar()
        assert g.revoked_at is not None
        assert not g.is_active

    def test_vencida_y_revocada_se_distinguen(self):
        """El registro necesita saber cuál de las dos fue: solo una es un
        incidente."""
        vencida = AccessGrant(
            subject_kind=GrantKind.WORKER,
            subject_id="proyecto-1",
            secret_hash="a" * 64,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        revocada = AccessGrant(
            subject_kind=GrantKind.WORKER,
            subject_id="proyecto-1",
            secret_hash="a" * 64,
            revoked_at=datetime.now(timezone.utc),
        )
        assert "venció" in vencida.motivo_de_rechazo()
        assert "revocada" in revocada.motivo_de_rechazo()

    def test_revocar_dos_veces_conserva_la_primera_fecha(self):
        g, _ = acunar(GrantKind.WORKER, "proyecto-1")
        g.revocar()
        primera = g.revoked_at
        g.revocar()
        assert g.revoked_at == primera


class TestLoQueLaCredencialNoAutoriza:
    """La parte que de verdad importa."""

    def test_una_credencial_no_satisface_una_comprobacion_de_rol(self):
        """Sin esto, quien tuviera el enlace de una sesión podría pedir la
        lista de participantes y las ejecuciones de todos."""
        for kind in ("worker", "participation"):
            llamante = CurrentUser(subject="x", role="investigador", kind=kind)
            with pytest.raises(HTTPException) as exc:
                llamante.require("investigador")
            assert exc.value.status_code == 403
            assert "cuenta de persona" in exc.value.detail

    def test_una_cuenta_si_la_satisface(self):
        CurrentUser(subject="u-1", role="investigador").require("investigador")

    def test_una_credencial_no_tiene_autor_que_declarar(self):
        assert CurrentUser("p-1", "x", kind="participation").user_id is None

    def test_una_participacion_no_actua_por_otro_participante(self):
        """Sin esta comprobación, la variable principal del experimento
        dejaría de ser atribuible: cualquiera escribiría decisiones a nombre de
        cualquiera."""
        llamante = CurrentUser("p-1", "participation", kind="participation")
        llamante.require_participation("p-1")
        with pytest.raises(HTTPException) as exc:
            llamante.require_participation("p-2")
        assert exc.value.status_code == 403

    def test_un_trabajador_no_opera_sobre_otro_proyecto(self):
        llamante = CurrentUser("proy-1", "worker", kind="worker")
        llamante.require_worker("proy-1")
        with pytest.raises(HTTPException):
            llamante.require_worker("proy-2")

    def test_una_cuenta_no_pasa_por_trabajador(self):
        """El camino inverso también se cierra: una cuenta de persona no es una
        credencial de máquina, por mucho rol que tenga."""
        with pytest.raises(HTTPException):
            CurrentUser("u-1", "lider_tecnico").require_worker("proy-1")


class TestPersistencia:
    async def test_ida_y_vuelta(self, session):
        repo = SqlAccessGrantRepository(session)
        grant, token = acunar(
            GrantKind.WORKER, "proyecto-1", label="portátil de Ana"
        )
        await repo.save(grant)
        vuelto = await repo.get(grant.id)
        assert vuelto is not None
        assert vuelto.subject_kind is GrantKind.WORKER
        assert vuelto.label == "portátil de Ana"
        # El secreto sigue casando después de pasar por la base.
        _, _, secreto = leer(token)
        assert vuelto.coincide(secreto)

    async def test_revocar_se_persiste(self, session):
        repo = SqlAccessGrantRepository(session)
        grant, _ = acunar(GrantKind.PARTICIPATION, "p-1")
        await repo.save(grant)
        assert await repo.revoke(grant.id)
        assert not (await repo.get(grant.id)).is_active

    async def test_revocar_lo_que_no_existe_lo_dice(self, session):
        assert not await SqlAccessGrantRepository(session).revoke("no-existe")

    async def test_se_anota_el_uso(self, session):
        """Una credencial activa que nadie esperaba se detecta por aquí."""
        repo = SqlAccessGrantRepository(session)
        grant, _ = acunar(GrantKind.WORKER, "proyecto-1")
        await repo.save(grant)
        assert (await repo.get(grant.id)).last_used_at is None
        await repo.touch(grant.id)
        assert (await repo.get(grant.id)).last_used_at is not None

    async def test_se_listan_las_del_sujeto_y_solo_esas(self, session):
        repo = SqlAccessGrantRepository(session)
        for _ in range(2):
            g, _ = acunar(GrantKind.WORKER, "proyecto-1")
            await repo.save(g)
        otro, _ = acunar(GrantKind.WORKER, "proyecto-2")
        await repo.save(otro)
        participacion, _ = acunar(GrantKind.PARTICIPATION, "proyecto-1")
        await repo.save(participacion)

        de_uno = await repo.list_for(GrantKind.WORKER, "proyecto-1")
        assert len(de_uno) == 2
        assert all(g.subject_id == "proyecto-1" for g in de_uno)


class TestFechasSinZona:
    """SQLite devuelve fechas sin zona horaria aunque la columna la declare.

    PostgreSQL las devuelve con ella, de modo que sin esta normalización el
    vencimiento reventaba en local y funcionaba en el despliegue, que es la
    peor forma de tener un fallo.
    """

    def test_una_fecha_sin_zona_se_lee_como_utc(self):
        g = AccessGrant(
            subject_kind=GrantKind.WORKER,
            subject_id="proyecto-1",
            secret_hash="a" * 64,
            expires_at=datetime(2027, 1, 1, 0, 0),  # sin zona, como SQLite
        )
        assert g.expires_at.tzinfo is not None
        assert g.is_active  # y comparar no revienta

    async def test_la_vuelta_de_la_base_no_revienta(self, session):
        repo = SqlAccessGrantRepository(session)
        grant, _ = acunar(GrantKind.WORKER, "proyecto-1")
        await repo.save(grant)
        assert (await repo.get(grant.id)).is_active
