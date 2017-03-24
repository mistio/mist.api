FROM gcr.io/mist-ops/alpine:3.4

COPY requirements.txt /mist.api/requirements.txt

WORKDIR /mist.api/

RUN pip install --no-cache-dir -r /mist.api/requirements.txt

COPY libcloud /mist.api/libcloud

RUN pip install -e libcloud/

COPY run_script /mist.api/run_script

COPY . /mist.api/

RUN rm src/pip-delete-this-directory.txt

RUN pip install -e src/
