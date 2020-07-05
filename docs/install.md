# ddosdn installation
## Build Instructions
### OS Requirements
ddosdn is developed and has primary testing on Ubuntu 18.04.

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

#### 1. containernet
 
 ```
 sudo apt-get install ansible git aptitude
 git clone https://github.com/containernet/containernet.git
 cd containernet/ansible
 sudo ansible-playbook -i "localhost," -c local install.yml
 cd ..
 ```
 * for Ubutu 20.04 replace in `containernet/util/install.sh` 
     * `cgroup-bin` for `cgroup-tools` , 
     * `python-scapy` for `python3-scapy`
     
     run `containernet/util/install.sh`, NOTE: there are some compiling erros
     whit Openflow but ignore those. and install mininet 
    
     ```
     apt install mininet
     
     make -f Makefile develop
     ```

#### 2. Enviroment
 
 ```
 git clone https://github.com/ser0090/ddosdn
 cd ddosdn/envr
 
 docker-compose build snort
 docker-compose build apache
 docker-compose build bot
 docker-compose build usr
 ```
 
#### 3. Onos
 
 Add onos 1.13 commands to bashrc. get onos 1.13
 
 ``` 
 wget https://github.com/opennetworkinglab/onos/archive/1.13.10.tar.gz 
 tar -xf 1.13.10.tar.gz
 ```
 
 add to .bashrc
 
 ```
 export ONOS_ROOT=~/onos-1.13.10
 source $ONOS_ROOT/tools/dev/bash_profile
 ```
 
 up onos 1.13
 
 ``` 
 docker-compose up onos
 ```

### Building apps

#### 1. onos apps
in ddosdn folder build apps

```
cd apps

mvn clean install -f ddos-detection/ -Dcheckstyle.skip
mvn clean install -f ddos-mitigation/ -Dcheckstyle.skip
```

### Install Apps
then install apps in onos controller (docker container),

Required Apps

```bash
IP_CONTAINER=192.168.60.2 # IP controller

onos-app ${IP_CONTAINER} activate org.onosproject.openflow-base # App Openflow
onos-app ${IP_CONTAINER} activate org.onosproject.openflow 
onos-app ${IP_CONTAINER} activate org.onosproject.ofagent

onos-app ${IP_CONTAINER} activate org.onosproject.faultmanagement # alarms REST
```

Built Apps

```
onos-app ${IP_CONTAINER} reinstall! ddos-detection/target/*.oar
onos-app ${IP_CONTAINER} reinstall! ddos-mitigation/target/*.oar
```

### Config test enviroment 

Start Containernet Topology

```
cd topo
pip3 install -e .
```

Config annotations devices on Onos 
```
onos-netcfg ${IP_CONTAINER} resources/jsonAnnotations.json
```

### Run topology

```
python3 topo.py
```

