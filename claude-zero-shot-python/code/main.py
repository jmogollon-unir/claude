"""
API FastAPI para consultar los detalles de un usuario en PostgreSQL.

Ejecutar:
    uvicorn main:app --reload

Probar:
    GET http://127.0.0.1:8000/users/1
"""
import os
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, HTTPException, Path, Request

# Configuración por variables de entorno (evita credenciales en el código)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/mi_base_de_datos",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Se crea un pool de conexiones al iniciar la aplicación
    app.state.pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
    yield
    # Se cierra el pool al detener la aplicación
    await app.state.pool.close()


app = FastAPI(title="API de usuarios", lifespan=lifespan)


@app.get("/users/{user_id}")
async def get_user(
    request: Request,
    user_id: int = Path(..., gt=0, description="ID del usuario"),
):
    """Retorna los detalles de un usuario en formato JSON."""
    # Consulta parametrizada ($1) para prevenir inyección SQL.
    # Ajusta las columnas y la tabla a tu esquema real.
    query = """
        SELECT id, name, email, created_at
        FROM users
        WHERE id = $1
    """
    try:
        async with request.app.state.pool.acquire() as conn:
            row = await conn.fetchrow(query, user_id)
    except asyncpg.PostgresError:
        raise HTTPException(status_code=500, detail="Error al consultar la base de datos")

    if row is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return dict(row)  # FastAPI serializa el dict (incluidas fechas) a JSON
