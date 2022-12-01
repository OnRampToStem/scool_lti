FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && useradd app

RUN pip install --upgrade pip wheel

WORKDIR /app

COPY requirements.txt .

RUN pip install -r requirements.txt \
    && rm -rf ~/.cache/pip

COPY . .

USER app

CMD ["gunicorn", "scale_api.app:app"]

EXPOSE 8000
