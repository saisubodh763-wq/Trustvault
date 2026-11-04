FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 10001 tv && mkdir -p /data && chown tv /data
USER tv
ENV TRUSTVAULT_DATA=/data TRUSTVAULT_ENV=production PORT=8000
VOLUME /data
EXPOSE 8000
# ONE worker: SQLite is a single-writer store and the authorisation transactions rely on it.
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 8 --bind 0.0.0.0:${PORT} --access-logfile - wsgi:app"]
