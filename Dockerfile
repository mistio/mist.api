FROM python:3.7-slim-buster

# Install libvirt which requires system dependencies.
RUN apt update && apt install -y build-essential g++ gcc libvirt-dev \
    libxml2-dev libxslt-dev gnupg ca-certificates wget python3-pip \
    mongo-tools libmemcached-dev netcat build-essential libssl-dev libffi-dev \
    python3-dev cargo zlib1g-dev git && \
    rm -rf /var/lib/apt/lists/*

# Install golang
RUN wget https://golang.org/dl/go1.17.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz && \
    git clone https://gitlab.ops.mist.io/mistio/victoriametricsrbac.git && \
    cd victoriametricsrbac && export PATH=$PATH:/usr/local/go/bin && go build -buildmode=c-shared -o promql_rbac.so

RUN wget https://dl.influxdata.com/influxdb/releases/influxdb-1.8.4-static_linux_amd64.tar.gz && \
    tar xvfz influxdb-1.8.4-static_linux_amd64.tar.gz && rm influxdb-1.8.4-static_linux_amd64.tar.gz

RUN ln -s /influxdb-1.8.4-1/influxd /usr/local/bin/influxd && \
    ln -s /usr/bin/pip3 /usr/bin/pip && \
    ln -s /usr/bin/python3 /usr/bin/python

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade setuptools && \
    pip install libvirt-python==7.2.0 uwsgi==2.0.19.1 && \
    pip install --no-cache-dir ipython ipdb flake8 pytest pytest-cov

# Remove `-frozen` to build without strictly pinned dependencies.
COPY requirements-frozen.txt /mist.api/requirements.txt
COPY requirements-frozen.txt /requirements-frozen-mist.api.txt
COPY requirements.txt /requirements-mist.api.txt

WORKDIR /mist.api/

COPY paramiko /mist.api/paramiko
COPY libcloud /mist.api/libcloud
COPY v2 /mist.api/v2

RUN pip install --no-cache-dir -r /mist.api/requirements.txt && \
    pip install -e paramiko/ && \
    pip install -e libcloud/ && \
    pip install -e v2/ && \
    pip install --no-cache-dir -r v2/requirements.txt

COPY . /mist.api/

RUN pip install -e src/

# This file gets overwritten when mounting code, which lets us know code has
# been mounted.
RUN touch clean

ENTRYPOINT ["/mist.api/bin/docker-init"]

ARG API_VERSION_SHA
ARG API_VERSION_NAME

# Variables defined solely by ARG are accessible as environmental variables
# during build but not during runtime. To persist these in the image, they're
# redefined as ENV in addition to ARG.
ENV JS_BUILD=1 \
    VERSION_REPO=mistio/mist.api \
    VERSION_SHA=$API_VERSION_SHA \
    VERSION_NAME=$API_VERSION_NAME


RUN echo "{\"sha\":\"$VERSION_SHA\",\"name\":\"$VERSION_NAME\",\"repo\":\"$VERSION_REPO\",\"modified\":false}" \
        > /mist-version.json
