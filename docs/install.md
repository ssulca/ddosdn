# ddosdn installation
## Build Instructions
### OS Requirements
ddosdn is developed and has primary testing on Ubuntu 18.04.

### Install Prerequisites
  * `docker`
  * `docker-compose`
  * Java 8
    ```bash
    sudo apt install openjdk-8-jdk
    ```
  * `maven`
  * [`openvswitch`](http://docs.openvswitch.org/en/latest/intro/install/distributions/#debian)
    ```bash
    sudo apt install openvswitch-common
    sudo apt install openvswitch-switch
    ```
  * [`containernet`](https://github.com/containernet/containernet)

### Installation

#### 1. Containernet

```bash
sudo apt-get install ansible git aptitude
git clone https://github.com/containernet/containernet.git
cd containernet/ansible
sudo ansible-playbook -i "localhost," -c local install.yml
cd ..
```
For Ubutu 20.04 replace in `containernet/util/install.sh`
* `cgroup-bin` for `cgroup-tools` ,
* `python-scapy` for `python3-scapy`

run `containernet/util/install.sh`.
> NOTE: there are some compiling erros whit Openflow but ignore those. and
> install mininet

```bash
apt install mininet
make -f Makefile develop
```

#### 2. Enviroment

 ```bash
 git clone https://github.com/ser0090/ddosdn
 cd ddosdn/envr

 docker-compose build snort
 docker-compose build apache
 docker-compose build bot
 docker-compose build usr
 ```

#### 3. Onos
 This projecs use `onos-1.13` . We suggest clone ONOS repositoy
 [here](https://github.com/opennetworkinglab/onos). Then add onos 1.13 commands
 to `.bashrc`

 ``` bash
wget https://github.com/opennetworkinglab/onos/archive/1.13.10.tar.gz
tar -xf 1.13.10.tar.gz
# add to .bashrc
export ONOS_ROOT=~/onos-1.13.10
source $ONOS_ROOT/tools/dev/bash_profile
```
> We suggest up onos 1.13 in a docker container instead of up locally

```bash
docker-compose up onos
```

### Building apps

#### 1. onos apps
in ddosdn folder build apps

```bash
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

```bash
onos-app ${IP_CONTAINER} reinstall! ddos-detection/target/*.oar
onos-app ${IP_CONTAINER} reinstall! ddos-mitigation/target/*.oar
```

### Config test enviroment

Start Containernet Topology

```bash
cd topo
pip3 install -e .
```

Config annotations devices on Onos
```bash
onos-netcfg ${IP_CONTAINER} resources/jsonAnnotations.json
```

### Run topology

```bash
python3 topo.py
```

