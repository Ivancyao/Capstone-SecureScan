# Imagen del backend. Partimos de Python 3.12 en su versión "slim" (liviana).
FROM python:3.12-slim

# nmap: lo usa el motor de escaneo
# (lo instalo con el sistema porque el backend lo ejecuta como un programa aparte; "rm" de abajo borra la caché
# de apt para que la imagen pese menos)
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
# Copio primero solo requirements.txt: así Docker reutiliza la capa de las librerías mientras no cambien,
# y no reinstala todo cada vez que modifico el código.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Recién ahora copio el código de la aplicación.
COPY app ./app
# EXPOSE solo documenta el puerto; el que realmente se publica es el de docker-compose.yml.
EXPOSE 8000
# Arranca la API. Con 0.0.0.0 acepta conexiones desde fuera del contenedor (si no, solo escucharía dentro).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
