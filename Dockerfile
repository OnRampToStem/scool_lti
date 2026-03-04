FROM public.ecr.aws/docker/library/python:3.14.3-slim

LABEL org.opencontainers.image.source=https://github.com/OnRampToStem/scool_lti

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -y && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && openssl req -x509 -nodes -batch -newkey rsa:2048 \
            -keyout /etc/ssl/key.pem \
            -out /etc/ssl/cert.pem \
            -days 395 \
            -subj "/C=US/ST=California/L=Fresno/O=Fresno State/OU=TS/CN=scool-lti.priv.fresnostate.edu" \
    && chmod 444 /etc/ssl/*.pem

WORKDIR /app

RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-cache --no-dev --no-python-downloads --compile-bytecode

COPY . .

RUN /app/.venv/bin/python -m compileall -f -q scool

USER nobody

CMD ["/app/.venv/bin/python", "-m", "scool"]

EXPOSE 8443
