FROM public.ecr.aws/docker/library/python:3.12.6-slim

ENV DEBIAN_FRONTEND=noninteractive

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV PIP_ROOT_USER_ACTION=ignore
ENV PIP_NO_CACHE_DIR=off
ENV PIP_PROGRESS_BAR=off
ENV PIP_COMPILE=1

RUN apt-get update -y && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && openssl req -x509 -nodes -batch -newkey rsa:2048 \
            -keyout /etc/ssl/key.pem \
            -out /etc/ssl/cert.pem \
            -days 395 \
            -subj "/C=US/ST=California/L=Fresno/O=Fresno State/OU=TS/CN=scool-lti.priv.fresnostate.edu" \
    && chmod 644 /etc/ssl/*.pem \
    && adduser -u 999 --group --system app

WORKDIR /app

COPY requirements.txt .

RUN python3.12 -m pip install --upgrade pip \
    && python3.12 -m pip install -r requirements.txt \
    && python3.12 -m pip list

COPY . .

RUN python3.12 -m compileall -f -q scool

USER app

CMD ["python3.12", "-m", "scool", "prod"]

EXPOSE 8443
