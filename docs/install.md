# ddosdn installation
## Build Instructions
### OS Requirements
Verilator is developed and has primary testing on Ubuntu.

### Install Prerequisites
  * [`docker-ce`](https://docs.docker.com/engine/install/ubuntu/)
  * `docker-compose`
  * [`openvswitch`](http://docs.openvswitch.org/en/latest/intro/install/distributions/#debian)
  ```
  apt install openvswitch-common
  apt install openvswitch-switch
  ```
  * `Java 8`
  ```
  apt install openjdk-8-jdk
  ```
  * `maven`  
  * [`containernet`](https://github.com/containernet/containernet)

### Installation

 1. containernet
 ```
 sudo apt-get install ansible git aptitude
 git clone https://github.com/containernet/containernet.git
 cd containernet/ansible
 sudo ansible-playbook -i "localhost," -c local install.yml
 cd ..
 ```
  * for Ubutu 20.04
     replace in `containernet/util/install.sh` 
     
     * `cgroup-bin` for `cgroup-tools` , 
     * `python-scapy` for `python3-scapy`
     
     ```
     apt install mininet
     ```
 ```
 make -f Makefile develop
 ```
 2. Enviroment
 
 ```
 git clone https://github.com/ser0090/ddosdn
 cd ddosdn/envr
 
 docker-compose build snort
 docker-compose build apache
 docker-compose build bot
 docker-compose build usr
 ```

#### in progress ...
