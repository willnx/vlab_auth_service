FROM willnx/vlab-base
RUN mkdir -p /etc/vlab/auth_server && chown nobody /etc/vlab/auth_server
COPY dist/*.whl /tmp

RUN pip install /tmp/*.whl && rm /tmp/*.whl
RUN apk del gcc
WORKDIR /usr/lib/python3.8/site-packages/vlab_auth_service
CMD uwsgi --need-app --ini ./app.ini
