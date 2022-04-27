# ddosdn
Mitigation and Detection of DDoS Attacks in Software Defined Networks

## Table of Contents

- [About The Project](#about-the-project)
- [Built With](#built-with)
- [Getting started](#getting-started)
- [Usage](#usage)
- [License](#license)
- [Credits](#credits)

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

We implements two apps in order to detect and mitigate DDoS flow and then using
a Virtual enviroment tath contains a vitual topology like ISP, and these are
based on **Fang-Yie Leu, I-Long Lin, "A DoS/DDoS Attack Detection System Using
Chi-Square Statistic Approach"**.
[pdf](http://www.iiisci.org/journal/CV$/sci/pdfs/GI137NK.pdf)

To test SDN apps, we use [ONOS](https://onosproject.org/) SDN controller.

## Built With
SDN applications
 * [Onos](https://github.com/opennetworkinglab/onos) 1.13
 * maven v3+
 * java 8

Test enviroment
 * [Docker](https://www.docker.com/)
 * Docker-compose
 * [OpenVSwitch](https://www.openvswitch.org/) v2.9+
 * [Containernet](https://github.com/containernet/containernet)

## Getting started
See the installation [guide](./docs/install.md).

## Usage
See the [documentation](./docs/use.md) to get started with `ddosdn`.

Also you can watch a demo [video](https://youtu.be/oPERE8d_F40).

## License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## Credits
### Cite this work
If you use `ddosdn` for your research and/or other publications.

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

### Authors

* **López Gastón** - *Initial work* - [GastonLopez](https://github.com//GastonLopez)
* **Sergio Sulca** - *Initial work* - [ssulca](https://github.com/ssulca)

### Acknowledgments

* **ONOS Developers Group** - [onos-dev](https://groups.google.com/a/onosproject.org/forum/#!forum/onos-dev)
* **Tomattis Natasha** - [natitomattis](https://github.com/natitomattis)
* **FULGOR FUNDATION** [fulgor](http://www.fundacionfulgor.org.ar/sitio/index.php)
