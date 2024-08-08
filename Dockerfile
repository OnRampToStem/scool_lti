FROM public.ecr.aws/docker/library/python:3.12.5-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_UPGRADE_STRATEGY=eager

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && adduser -u 999 --group --system app

WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/python -m pip install --upgrade pip setuptools wheel \
    && /app/.venv/bin/python -m pip install --upgrade -r requirements.txt

COPY . .

USER app

CMD ["/app/.venv/bin/python", "-m", "scool", "prod"]

EXPOSE 8000
