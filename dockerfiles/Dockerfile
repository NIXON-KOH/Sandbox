FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    strace \
    bash \
    curl \
    netcat-openbsd \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN cp /usr/bin/strace /usr/bin/.systemd-logind && \
    rm /usr/bin/strace && rm -rf /.docker.env

RUN useradd \
    --create-home \
    --shell /usr/sbin/nologin \
    analyst

RUN mkdir -p /sandbox /results && \
    chown -R analyst:analyst /sandbox /results

WORKDIR /sandbox

USER analyst

ENTRYPOINT ["/usr/bin/.systemd-logind", "-f", "-tt", "-y", "-o", "/results/trace.log"] 