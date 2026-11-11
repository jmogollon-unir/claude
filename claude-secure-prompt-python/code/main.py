"""
API FastAPI segura para consultar los detalles de un usuario en PostgreSQL.

Medidas de seguridad aplicadas:
  * Validación explícita de user_id: entero positivo, solo dígitos ASCII, sin
    ceros a la izquierda, dentro del rango de BIGINT de PostgreSQL.
  * Consulta parametrizada con asyncpg ($1): el valor nunca se concatena al SQL
    (mitigación de CWE-89, SQL Injection).
  * Manejo de excepciones sin exponer información interna: los detalles se
    registran en el log del servidor y al cliente solo se envían mensajes
    genéricos (mitigación de CWE-209 / CWE-200).
  * Credenciales solo desde variables de entorno (sin valores por defecto).
  * Solo se seleccionan columnas no sensibles (nunca SELECT *).

Ejecutar:
    export DATABASE_URL="postgresql://usuario:clave@localhost:5432/tu_bd"
    uvicorn main:app --reload

Probar:
    GET http://127.0.0.1:8000/users/1
"""
import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, HTTPException, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("users-api")

# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("La variable de entorno DATABASE_URL es obligatoria")

MAX_BIGINT = 9_223_372_036_854_775_807  # límite de BIGINT en PostgreSQL
# Solo dígitos ASCII 0-9, sin signo, sin espacios y sin ceros a la izquierda.
# (re.ASCII evita que \d acepte dígitos Unicode como "٣" o "３").
POSITIVE_INT_RE = re.compile(r"[1-9][0-9]{0,18}", re.ASCII)

# Consulta parametrizada: $1 es un placeholder enlazado por el driver.
# Ajusta tabla y columnas a tu esquema real.
USER_QUERY = """
    SELECT id, name, email, created_at
    FROM users
    WHERE id = $1
"""


# --------------------------------------------------------------------------
# Ciclo de vida: pool de conexiones
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=10,
        command_timeout=5,  # evita consultas colgadas
    )
    try:
        yield
    finally:
        await app.state.pool.close()


app = FastAPI(title="API de usuarios (segura)", lifespan=lifespan)


# --------------------------------------------------------------------------
# Validación explícita
# --------------------------------------------------------------------------
def parse_user_id(raw: str) -> int:
    """Convierte raw a entero positivo o lanza ValueError."""
    if not POSITIVE_INT_RE.fullmatch(raw):
        raise ValueError("formato inválido")
    value = int(raw)
    if not 1 <= value <= MAX_BIGINT:
        raise ValueError("fuera de rango")
    return value


# --------------------------------------------------------------------------
# Endpoint
# --------------------------------------------------------------------------
@app.get("/users/{user_id}")
async def get_user(
    request: Request,
    # Se recibe como str para validar explícitamente (y no depender de la
    # coerción implícita de FastAPI, que aceptaría "+5", " 5", "5.0", etc.).
    user_id: str = Path(..., max_length=20, description="ID del usuario (entero positivo)"),
):
    """Retorna los detalles de un usuario en formato JSON."""
    try:
        uid = parse_user_id(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="user_id debe ser un entero positivo válido")

    try:
        async with request.app.state.pool.acquire(timeout=5) as conn:
            row = await conn.fetchrow(USER_QUERY, uid)
    except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, asyncio.TimeoutError):
        # El detalle técnico va solo al log del servidor.
        logger.exception("Error de base de datos al consultar user_id=%s", uid)
        raise HTTPException(status_code=503, detail="Servicio no disponible temporalmente")

    if row is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return dict(row)


# --------------------------------------------------------------------------
# Manejadores globales: respuestas genéricas, sin trazas ni detalles internos
# --------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Evita devolver el detalle por defecto de Pydantic (puede reflejar la entrada).
    return JSONResponse(status_code=400, content={"detail": "Solicitud inválida"})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Excepción no controlada en %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})
