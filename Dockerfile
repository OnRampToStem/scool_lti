FROM python:3.11.3-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libpq-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && useradd app

WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/pip install -r requirements.txt

COPY . .

USER app

CMD ["/app/.venv/bin/python", "-m", "scale_api", "prod"]

EXPOSE 8000
