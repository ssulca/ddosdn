# Snort in Docker
# Modify original Jhohn-Lin project https://github.com/John-Lin/docker-snort

FROM ubuntu:18.04

LABEL version="2.0" \
      description="Snort 2.9.16 docker-container" \
      maintainer="ser0090"

RUN apt-get update && \
    apt-get install -y \
    wget \
    build-essential \
    gcc \
    tcpdump \
    vim

RUN apt-get install -y \
    libdnet \
    libdaq2 \
    libpcap-dev \
    libpcre3-dev \
    zlib1g-dev \
    libluajit-5.1-dev \
    openssl \
    libssl-dev \
    libnghttp2-dev \
    libdumbnet-dev \
    bison \
    flex \
    libdnet \
    libnetfilter-queue1 \
    libdumbnet-dev \
    autoconf \
    libtool \
    iptables-dev \
    unzip 

# Python
RUN apt-get install -y \
    python-setuptools \
    python-pip \
    python-dev

RUN pip install -U pip dpkt snortunsock

# Define working directory.
WORKDIR /opt

ENV DAQ_VERSION 2.0.7
RUN wget https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz \
    && tar xvfz daq-${DAQ_VERSION}.tar.gz \
    && cd daq-${DAQ_VERSION} \
    && ./configure; make; make install

# change ENV SNORT_VERSION 2.9.8.2
ENV SNORT_VERSION 2.9.16
#RUN wget https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz \
RUN wget https://www.snort.org/downloads/archive/snort/snort-${SNORT_VERSION}.tar.gz \
    && tar xvfz snort-${SNORT_VERSION}.tar.gz \
    && cd snort-${SNORT_VERSION} \
    && ./configure; make; make install

RUN ldconfig

# snortunsock
RUN wget --no-check-certificate \
    https://github.com/John-Lin/snortunsock/archive/master.zip \
    && unzip master.zip

# Agregado de variables de entorno
RUN ln -s /usr/local/bin/snort /usr/sbin/snort

# comunicacion unixsock python
RUN apt-get install -y \
    iputils-ping \
    net-tools \
    iputils-ping \
    iproute2 

# ENV SNORT_RULES_SNAPSHOT 2972
# ADD snortrules-snapshot-${SNORT_RULES_SNAPSHOT} /opt

ADD mysnortrules /opt

RUN mkdir -p /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort && \

    # mysnortrules rules
    cp -r /opt/rules /etc/snort/rules && \
    # Due to empty folder so mkdir
    mkdir -p /etc/snort/preproc_rules && \
    mkdir -p /etc/snort/so_rules && \
    cp -r /opt/etc /etc/snort/etc && \

    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

RUN chmod 5775 -R /etc/snort && \
    chmod 5775 -R /var/log/snort &&\
    chmod 5775 -R /usr/local/lib/snort_dynamicrules

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/snort-${SNORT_VERSION}.tar.gz /opt/daq-${DAQ_VERSION}.tar.gz

RUN pip install netifaces # get interfaces ip
ADD dev /opt

# ENV NETWORK_INTERFACE eth0
# Validate an installation
# snort -T -i eth0 -c /etc/snort/etc/snort.conf
# CMD ["snort", "-T", "-i", "echo ${NETWORK_INTERFACE}", "-c", "/etc/snort/etc/snort.conf"]

# commando para que evitar snort-container se cierre
# CMD ["snort", "-i", "eth0", "-c", "/etc/snort/etc/snort.conf", "-A", "console"]
CMD ["./start.sh"]
# comando para que Snort envie por socket los datos.
#CMD ["snort", "-i", "eth1", "-c", "/etc/snort/etc/snort.conf", "-l", "/tmp"]
