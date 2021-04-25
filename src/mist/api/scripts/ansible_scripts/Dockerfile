# TODO build Image to mist images
FROM alpine:3.13

# TODO Install from pip?
RUN apk add ansible

COPY ./ansible_runner /opt/ansible_runner

ENTRYPOINT ["/opt/ansible_runner"]
