FROM alpine:3.7
MAINTAINER Nicholas Willhite (willnx84@gmail.com)

RUN apk update && apk upgrade
RUN apk add wget python3 python3-dev openssl openssl-dev gcc \
            linux-headers libc-dev libffi-dev pcre pcre-dev
RUN wget -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py && \
    python3 /tmp/get-pip.py && \
    rm /tmp/get-pip.py
RUN mkdir -p /etc/vlab/auth_service
COPY dist/*.whl /tmp

RUN pip install /tmp/*.whl && rm /tmp/*.whl
RUN apk del gcc
WORKDIR /usr/lib/python3.6/site-packages/vlab_auth_service
CMD uwsgi --ini ./app.ini
