# ONOS Apps
Apps developed using Java 
### ddos-deteccion

*Duplicate suspicious traffic.*
<p style="text-align: center;">
<img src=ddos-detection/cap4.png width=50%>
</p>

Dependence: 

`ddos-detection/pom.xml`

### ddos-mitigation

*Filtrate suspicious traffic.*
<p style="text-align: center;">
<img src=ddos-mitigation/cap5.png width=50%>
</p>

Dependence: 

`ddos-mitigation/pom.xml`

### Prerequisites
 * jdk-8
 * maven

### Built
command `mci` (maven clean install) using `-Dcheckstyle.skip` to igonre coding
standards.

```bash
mvn clean install -f ddos-detection/ -Dcheckstyle.skip
mvn clean install -f ddos-mitigation/ -Dcheckstyle.skip
```
### Install
Install and activate Apps in ONOS controller
```bash
onos-app <ip_controller> install! ddos-detection/target/ddos-detection-1.0-SNAPSHOT.oar
onos-app <ip_controller> install! ddos-mitigation/target/ddos-mitigation-1.0-SNAPSHOT.oar
```

