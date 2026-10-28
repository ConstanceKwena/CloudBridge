FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system cloudbridge && useradd --system --gid cloudbridge --create-home cloudbridge
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./backend/app
COPY migrations ./backend/migrations
COPY alembic.ini ./alembic.ini

USER cloudbridge
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1
CMD ["sh", "-c", "python -m alembic upgrade head && exec python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000"]