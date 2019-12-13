FROM httpd:latest

LABEL version="1.0" \
      description="Apache 2.4 docker-container"

RUN apt-get update && \
    apt-get install -y \
    net-tools \
    iputils-ping \
    libcgi-session-perl \
    iproute2 \
    tcpdump \
    build-essential 

ADD public-html/ /usr/local/apache2/htdocs/
ADD httpd.conf /usr/local/apache2/conf/
ADD cgi/ /usr/local/apache2/cgi-bin

WORKDIR /usr/local/apache2/cgi-bin
RUN make
CMD ["httpd-foreground"]
