FROM ubuntu:trusty

LABEL version="1.0" \
      description="User 1.0.0 docker-monitoring" \
      maintainer="Gaston Lopez <lopez.gaston.1996@gmail.com>"

RUN apt-get update && \
  apt-get install -y curl && \
  apt-get install -y siege && \
  apt-get install -y iproute2 

WORKDIR /root
ADD files /root

CMD ["siege -c5 -t 2H -i -f urls.txt"]
