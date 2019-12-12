# Usuario Legitimo con Monitoreo in Docker

FROM ubuntu:trusty

LABEL version="1.0" \
      description="UserLegitimo 1.0.0 docker-monitoring" \
      maintainer="Gaston Lopez <lopez.gaston.1996@gmail.com>"

RUN apt-get update && \
  apt-get install -y siege && \
  apt-get install nano && \
  apt-get install -y python && \
  apt-get install -y curl && \
  apt-get install -y vim
#RUN apt-get install -y python-pip

RUN apt-get install -y python-numpy && \
  apt-get install -y python-scipy

RUN apt-get install -y \
  dnsutils
WORKDIR /home
ADD files /home
# ADD SimularStats /home

CMD ["siege -c5 -t 2H -i -f urls.txt"]
