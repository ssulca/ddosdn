# Hacker DDOS in Docker (HPING3, TFN2K)

FROM ubuntu:trusty

LABEL version="1.0" \
      description="Bot 1.0.0 docker-bot" \
      maintainer="Gaston Lopez <lopez.gaston.1996@gmail.com>"

RUN apt-get update && \
  apt-get install nano && \
  apt-get install -y python && \
  apt-get install -y hping3 && \
  apt-get install -y curl &&\
  apt-get install -y git && \
  apt-get install -y vim

#RUN apt-get install -y python-pip

RUN apt-get install -y python-numpy && \
  apt-get install -y python-scipy

RUN cd /home/ && \
  git clone https://github.com/jseidl/GoldenEye.git

WORKDIR /home

#ADD DDOStfn2k /home
# ADD HPING3Tools /home
# ADD Targa3 /home
# ADD Slowloris /home
# ADD SimularStats /home

CMD ["bash"]
