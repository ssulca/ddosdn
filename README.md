# ddosdn
Mitigation and Detection of DDoS Attacks in Software Defined Networks

<!-- ABOUT THE PROJECT -->
## About The Project
This is a final project degree for computer enginering at
[UNC](https://www.unc.edu.ar/english/). It contains:
 
 * Virtual test enviroment
 * Detection App on SDN Control layer
 * Mitigation App on SDN Control layer
 * Managment App on external Aplication Layer

We implements these apps in order to detect and mitigate DDoS flow and then
using a Virtual enviroment tath contains a vitual topology like ISP, to test SDN
apps. We use [ONOS](https://onosproject.org/) SDN controller. 

## Built With
SDN applications
 * Maven
 
 Test enviroment
 * Docker
 * OpenVSwitch
 * ContainerNet

## Getting started
 This projecs use ONOS. We suggest clone ONOS repositoy
 [here](https://github.com/opennetworkinglab/onos)
 
### Prerequisites
 * Onos 1.13
 
Add the ONOS developer environment to your bash profile using step 2
[here](https://github.com/opennetworkinglab/onos#build-onos-from-source).

 * maven v3+
 * JDK 8
 * [Docker](https://www.docker.com/)
 * docker-compose
 * [Python2](https://www.python.org/downloads/release/python-272/)
 * [OpenVSwitch](https://www.openvswitch.org/) v2.9+
 * [Containernet](https://github.com/containernet/containernet)

 For OS based on debian use [this](https://github.com/containernet/containernet)
 and based in arch ContainerNet use
 [this](https://aur.archlinux.org/packages/containernet-git/)
 
### Installation
coming son

## License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## Authors

* **López Gastón** - *Initial work* - [GastonLopez](https://github.com//GastonLopez)
* **Sergio Sulca** - *Initial work* - [ser0090](https://github.com/ser0090)

## Acknowledgments

* **ONOS Developers Group** - [onos-dev](https://groups.google.com/a/onosproject.org/forum/#!forum/onos-dev)
* **Tomattis Natasha** - [natitomattis](https://github.com/natitomattis)

### Demo
Demo [video](https://youtu.be/oPERE8d_F40)
