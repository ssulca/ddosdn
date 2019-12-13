#!/usr/bin/env bash

white='\e[1;37;39m'
NC='\e[0m' # No Colo

clear
echo -e "${white} IDSs: ${HOSTNAME}"
echo -e "----------------------------------------------------------\n"
snort -i ${HOSTNAME}-eth0 -D -c /etc/snort/etc/snort.conf -l /tmp -k none
echo -e "${NC}"
