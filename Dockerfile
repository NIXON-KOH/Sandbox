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

RUN useradd \
    --create-home \
    --shell /usr/sbin/nologin \
    analyst

RUN mkdir -p /sandbox /results && \
    chown -R analyst:analyst /sandbox /results

WORKDIR /sandbox

USER analyst

ENTRYPOINT ["strace", "-f", "-tt", "-y", "-o", "/results/trace.log"] 