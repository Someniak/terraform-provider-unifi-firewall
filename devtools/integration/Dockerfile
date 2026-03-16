ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV UOS_SERVER_VERSION="5.0.6"
ENV FIRMWARE_PLATFORM="linux-x64"
ENV UOS_SYSTEM_IP="localhost"

COPY entrypoint.sh /root/entrypoint.sh
RUN chmod +x /root/entrypoint.sh

EXPOSE 443 8080 3478/udp 10003/udp

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/root/entrypoint.sh"]
