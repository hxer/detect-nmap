FROM debian:bullseye

ENV DEBIAN_FRONTEND noninteractive
WORKDIR /app

ENV NMAP_VERSION 7.80

COPY install_nmap.sh /install_nmap.sh

RUN apt update -yqq \
    && apt install -yqq --no-install-recommends \
        openssl ca-certificates \
        libssl-dev libssh2-1-dev \
        gcc g++ build-essential make libpcap-dev wget

RUN bash /install_nmap.sh

COPY nse/ /app/nse/
