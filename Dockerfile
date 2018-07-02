FROM willnx/vlab-base
RUN mkdir -p /etc/vlab/auth_service
COPY dist/*.whl /tmp

RUN pip install /tmp/*.whl && rm /tmp/*.whl
RUN apk del gcc
WORKDIR /usr/lib/python3.6/site-packages/vlab_auth_service
CMD uwsgi --ini ./app.ini
