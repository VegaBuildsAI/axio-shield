FROM python:3.12-slim

WORKDIR /app

# Dependencias (fijas, sin build local). anthropic es opcional en runtime (modo stub).
RUN pip install --no-cache-dir \
    "fastapi>=0.111" "uvicorn[standard]>=0.30" "pydantic>=2.7" \
    "pydantic-settings>=2.3" "anthropic>=0.39" "httpx>=0.27"

# Código + estáticos (portal, dashboard, sdk)
COPY backend /app/backend
COPY sdk /app/sdk
COPY demo-portal /app/demo-portal
COPY dashboard /app/dashboard
COPY arena /app/arena
COPY marketing /app/marketing
COPY simulator /app/simulator

ENV SHIELD_STATIC_ROOT=/app
ENV SHIELD_DB_PATH=/data/shield.db

WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
