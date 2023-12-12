FROM public.ecr.aws/docker/library/python:3.12.1-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd app

WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/pip install -r requirements.txt

COPY . .

USER app

CMD ["/app/.venv/bin/python", "-m", "scool", "prod"]

EXPOSE 8000
