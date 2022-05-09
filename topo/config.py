"""Constants."""
# IP de Docker 0.
IP_CONTROLLER = "192.168.50.2"
PORT_CONTROLLER = 6653

DI_SNORT = "snort"
DI_USER = "usr:latest"
DI_SERVER = "apache:latest"
DI_BOT = "bot:latest"

MEM_USER = "512m"
MEM_SERVER = "1024m"
MEM_BOT = "512m"
MEM_IDS = "512m"

# NET_CMD = 'sudo docker network connect docker_control_net %s'
OF_PROTOL = "OpenFlow14"
# Users Command
USER_CMD = "siege -c1 -t 40M -i -f urls.txt"

# Bandwidth
BW_CORE_TO_DISTRIBUTION = 500
BW_CORE_TO_CORE = 1000
BW_DISTRIBUTION_TO_EDGE = 300
BW_SERVER = 100
BW_CLIENT = 12
BW_IDS = 300
BW_DISTRIBUTION_TO_DISTRIBUTION = 500
