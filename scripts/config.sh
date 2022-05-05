#!/usr/bin/env bash

#Script para compilar las aplicaciones.
#Autores: Lopez Gaston, Sulca Sergio

blue='\e[0;49;36m'
red='\e[0;49;31m'
white='\e[1;37;39m'
NC='\e[0m' # No Color

ip_ctrl=192.168.60.2 #IP controlador

echo -e "${blue}Compiling..."
echo -e "${NC}"

#Compilacion de la aplicacion de mitigacion de ataques
mvn clean install -f ../../apps/ddos-mitigation -Dcheckstyle.skip
#Compilacion de la aplicacion de deteccion de anomalias
mvn clean install -f ../../apps/ddos-detection -Dcheckstyle.skip

#Instalar apps en ONOS.
echo -e "${blue}Intalling apps."
echo -e "${NC}"

if [ -z "$1" ]
then
    echo "default IP controller :${ip_ctrl}"
else
    ip_crtl="$1"
    echo "IP controller: ${ip_ctrl}"
fi

onos-app ${ip_ctrl} activate org.onosproject.openflow #App Openflow
#App historial de alarma
onos-app ${ip_ctrl} activate org.onosproject.faultmanagement

onos-app ${ip_ctrl} reinstall! ../../apps/ddos-mitigation/target/*.oar
# Reinstalacion de la aplicacion de deteccion de anomalias
onos-app ${ip_ctrl} reinstall! ../../apps/ddos-detection/target/*.oar

