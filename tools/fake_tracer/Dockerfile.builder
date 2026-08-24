
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y gcc make && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY fake_tracer.c Makefile ./
RUN make