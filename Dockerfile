FROM mist/alpine:3.4

# Install libvirt which requires system dependencies.
RUN apk add --update --no-cache libvirt libvirt-dev libxml2-dev libxslt-dev
RUN pip install libvirt-python==2.4.0

RUN pip install --no-cache-dir ipython pdb ipdb flake8 pytest pytest-cov

# Remove `-frozen` to build without strictly pinned dependencies.
COPY requirements-frozen.txt /mist.api/requirements.txt

WORKDIR /mist.api/

RUN pip install --no-cache-dir -r /mist.api/requirements.txt

COPY paramiko /mist.api/paramiko

RUN pip install -e paramiko/

COPY celerybeat-mongo /mist.api/celerybeat-mongo

RUN pip install -e celerybeat-mongo/

COPY libcloud /mist.api/libcloud

RUN pip install -e libcloud/

COPY . /mist.api/

RUN pip install -e src/

RUN touch clean

ENTRYPOINT ["/mist.api/bin/docker-init"]
