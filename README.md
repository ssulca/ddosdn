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

<p style="text-align: center;">
<img src=topo/images/onos_topo.png width=60%>
</p>

We implements these apps in order to detect and mitigate DDoS flow and then
using a Virtual enviroment tath contains a vitual topology like ISP, to test SDN
apps. We use [ONOS](https://onosproject.org/) SDN controller. It is based on A
DoS/DDoS Attack Detection System Using Chi-Square Statistic Approach Fang-Yie
Leu and I-Long Lin [pdf](http://www.iiisci.org/journal/CV$/sci/pdfs/GI137NK.pdf)

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
 * java 8
 * [Docker](https://www.docker.com/)
 * docker-compose
 * [OpenVSwitch](https://www.openvswitch.org/) v2.9+
 * [Containernet](https://github.com/containernet/containernet)

 For OS based on Debian use [this](https://github.com/containernet/containernet)
 and based on Arch ContainerNet use
 [this](https://aur.archlinux.org/packages/containernet-git/)
 
### Installation
 [guide](./docs/install.md)

### Using
 [use](./docs/use.md)

## Cite this work
If you use ddosdn for your research and/or other publications

Bibtex:

```bibtex
@techreport{ddosdn,
  author       = {G. Lopez and S. Sulca}, 
  title        = {Detección y mitigación de ataques DDoS dentro de una arquitectura SDN},
  institution  = {Facultad de Ciencias Exactas Fisicas y Naturales - UNC},
  year         = 2019,
  month        = 11
}
```

## License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## Authors

* **López Gastón** - *Initial work* - [GastonLopez](https://github.com//GastonLopez)
* **Sergio Sulca** - *Initial work* - [ser0090](https://github.com/ser0090)

## Acknowledgments

* **ONOS Developers Group** - [onos-dev](https://groups.google.com/a/onosproject.org/forum/#!forum/onos-dev)
* **Tomattis Natasha** - [natitomattis](https://github.com/natitomattis)
* **FULGOR FUNDATION** [fulgor](http://www.fundacionfulgor.org.ar/sitio/index.php)

### Demo
Demo [video](https://youtu.be/oPERE8d_F40)
