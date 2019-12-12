FROM httpd:latest

LABEL version="1.0" \
      description="Apache 2.4 docker-container" \
      maintainer="Sergio Sulca <ser.0090@gmail.com>"

RUN apt-get update && \
    apt-get install -y \
    net-tools \
    iputils-ping \
    libcgi-session-perl \
    nano \
    iproute2 \
    tcpdump \
    python \
    python-dev \
    python-pip

RUN pip install Flask &&\
  pip install simplejson

RUN apt-get install -y \
  dnsutils \
  vim

COPY ./public-html/ /usr/local/apache2/htdocs/
COPY httpd.conf /usr/local/apache2/conf/
COPY ./cgi/ /usr/local/apache2/cgi-bin

RUN cd /usr/local/apache2/cgi-bin &&\
    make

CMD ["httpd-foreground"]
