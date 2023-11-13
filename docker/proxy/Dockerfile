FROM httpd:2.4

RUN apt-get update -y && apt-get install -y --no-install-recommends \
		ca-certificates \
		openssl \
    && rm -rf /var/lib/apt/lists/* \
    && openssl req -x509 -nodes -batch -newkey rsa:2048 \
        -keyout /etc/ssl/private/server.key \
        -out /etc/ssl/certs/server.pem \
        -days 365 \
        -subj "/C=US/ST=California/L=Fresno/O=Fresno State/OU=TS/CN=scool.fresnostate.edu"

COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf

EXPOSE 80 443
