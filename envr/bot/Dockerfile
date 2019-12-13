FROM ubuntu:trusty

LABEL version="1.0" \
      description="Bot 2.0.0 docker-bot" \
      maintainer="Gaston Lopez <lopez.gaston.1996@gmail.com>"

RUN apt-get update && \
  apt-get install -y curl &&\
  apt-get install -y hping3 

WORKDIR /root

CMD ["bash"]
