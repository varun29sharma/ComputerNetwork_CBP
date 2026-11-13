# AegisX control plane (PDP): FastAPI + uvicorn.
FROM python:3.12-slim

WORKDIR /app

# Dependencies first, so rebuilds reuse the cached layer when only code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# 8000 is the PDP port used by the demo scripts (CP_PORT default).
EXPOSE 8000

# --host 0.0.0.0: inside a container uvicorn must listen on all interfaces,
# not just the container's loopback, or the published port stays unreachable.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
