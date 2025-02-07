FROM public.ecr.aws/docker/library/python:3.13.2-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -y && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

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
