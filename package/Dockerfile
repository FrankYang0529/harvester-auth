FROM registry.suse.com/bci/bci-base:15.5

RUN zypper -n rm container-suseconnect && \
    zypper -n install curl gzip tar && \
    zypper -n clean -a && rm -rf /tmp/* /var/tmp/* /usr/share/doc/packages/* && \
    useradd -M harvester && \
    mkdir -p /var/lib/harvester/auth && \
    chown -R harvester /var/lib/harvester/auth /usr/local/bin

WORKDIR /var/lib/harvester/auth

ARG ARCH=amd64
ENV TINI_VERSION v0.19.0
ENV TINI_URL_amd64=https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini \
    TINI_URL_arm64=https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-arm64 \
    TINI_URL_s390x=https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-s390x \
    TINI_URL=TINI_URL_${ARCH}

RUN curl -sLf ${!TINI_URL} > /usr/bin/tini && chmod +x /usr/bin/tini

COPY entrypoint.sh harvester /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh

VOLUME /var/lib/harvester/auth
ENTRYPOINT ["entrypoint.sh"]
