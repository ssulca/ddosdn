#!/usr/bin/python3
"""Topology."""
import logging
import subprocess

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Containernet
from mininet.node import RemoteController  # ,Controller
from mininet.node import OVSSwitch

from config import (
    BW_CLIENT,
    BW_CORE_TO_CORE,
    BW_CORE_TO_DISTRIBUTION,
    BW_DISTRIBUTION_TO_DISTRIBUTION,
    BW_DISTRIBUTION_TO_EDGE,
    BW_IDS,
    BW_SERVER,
    DI_BOT,
    DI_SERVER,
    DI_SNORT,
    DI_USER,
    IP_CONTROLLER,
    MEM_BOT,
    MEM_IDS,
    MEM_SERVER,
    MEM_USER,
    OF_PROTOL,
    PORT_CONTROLLER,
    USER_CMD,
)


def topoloy():
    """Topologia final sobre ContainerNet
    `user_leg` usuarios legitimos,`bot` hosts bots infectados,
    `vict` servidores
    `dns` servidor DNS en la topologia, `ids` IDS snort sniffer.

    :return: `void`:
    """
    # setLogLevel('info')
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # ############################################
    #           Config Virtual Switches
    # ############################################
    cls = OVSSwitch

    # ############################################
    #           Config Controller
    # ############################################

    onos = RemoteController("onos", ip=IP_CONTROLLER, port=PORT_CONTROLLER)
    net = Containernet(controller=RemoteController, link=TCLink)
    logger.info("Adding controller")
    # info('*** Adding controller\n')
    net.addController(onos)

    # ############################################
    #           Docker containers.
    # ############################################
    logger.info("Adding docker containers")

    # --------------------------------------
    #       IDS: Snort 4.x
    # --------------------------------------

    ids = [
        net.addDocker(
            "ids1", ip="192.168.12.3/16", dimage=DI_SNORT, mem_limit=MEM_IDS, dmcd="./start.sh"
        ),
        net.addDocker(
            "ids2", ip="192.168.13.3/16", dimage=DI_SNORT, mem_limit=MEM_IDS, dmcd="./start.sh"
        ),
        net.addDocker(
            "ids3", ip="192.168.14.3/16", dimage=DI_SNORT, mem_limit=MEM_IDS, dmcd="./start.sh"
        ),
        net.addDocker(
            "ids4", ip="192.168.15.3/16", dimage=DI_SNORT, mem_limit=MEM_IDS, dmcd="./start.sh"
        ),
    ]

    # --------------------------------------
    #       USER: ubuntu trusty
    # --------------------------------------

    users = [
        net.addDocker(
            "user_leg0", ip="192.168.4.10/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg1", ip="192.168.4.11/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg2", ip="192.168.5.12/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg3", ip="192.168.5.13/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg4", ip="192.168.6.14/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg5", ip="192.168.6.15/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg6", ip="192.168.7.16/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg7", ip="192.168.7.17/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg8", ip="192.168.8.18/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg9", ip="192.168.8.19/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg10", ip="192.168.9.71/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
        net.addDocker(
            "user_leg11", ip="192.168.9.72/16", dimage=DI_USER, mem_limit=MEM_USER, dmcd=USER_CMD
        ),
    ]

    # --------------------------------------
    #       SERVER: Apache 2.4
    # --------------------------------------

    vict = [
        net.addDocker(
            "vict0",
            ip="192.168.10.5/16",
            dimage=DI_SERVER,
            mem_limit=MEM_SERVER,
            dmcd="httpd-foreground",
        ),
        net.addDocker(
            "vict1",
            ip="192.168.11.50/16",
            dimage=DI_SERVER,
            mem_limit=MEM_SERVER,
            dmcd="httpd-foreground",
        ),
        net.addDocker(
            "vict2",
            ip="192.168.11.51/16",
            dimage=DI_SERVER,
            mem_limit=MEM_SERVER,
            dmcd="httpd-foreground",
        ),
    ]

    # --------------------------------------
    #       BOT: Ubuntu trustu
    # --------------------------------------

    bots = [
        net.addDocker("bot0", ip="192.168.4.20/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot1", ip="192.168.5.21/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot2", ip="192.168.6.22/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot3", ip="192.168.7.23/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot4", ip="192.168.8.24/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot5", ip="192.168.9.25/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot6", ip="192.168.5.26/16", dimage=DI_BOT, mem_limit=MEM_BOT),
        net.addDocker("bot7", ip="192.168.8.27/16", dimage=DI_BOT, mem_limit=MEM_BOT),
    ]

    # ############################################
    #     IDS ADD NETS ONOS
    # ############################################
    subprocess.run(["docker", "network", "connect", "envr_control_net", "mn.ids1"])
    subprocess.run(["docker", "network", "connect", "envr_control_net", "mn.ids2"])
    subprocess.run(["docker", "network", "connect", "envr_control_net", "mn.ids3"])
    subprocess.run(["docker", "network", "connect", "envr_control_net", "mn.ids4"])

    # ############################################
    #               Switches
    # ############################################

    logger.info("Adding switches")
    # Core
    s1 = net.addSwitch("s1", cls=cls, protocols=OF_PROTOL)
    s2 = net.addSwitch("s2", cls=cls, protocols=OF_PROTOL)
    # Border
    s3 = net.addSwitch("s3", cls=cls, protocols=OF_PROTOL)
    # Distribution
    s4 = net.addSwitch("s4", cls=cls, protocols=OF_PROTOL)
    s5 = net.addSwitch("s5", cls=cls, protocols=OF_PROTOL)
    s6 = net.addSwitch("s6", cls=cls, protocols=OF_PROTOL)
    s7 = net.addSwitch("s7", cls=cls, protocols=OF_PROTOL)
    # Service
    s8 = net.addSwitch("s8", cls=cls, protocols=OF_PROTOL)
    s12 = net.addSwitch("s12", cls=cls, protocols=OF_PROTOL)
    # Access
    s9 = net.addSwitch("s9", cls=cls, protocols=OF_PROTOL)
    s10 = net.addSwitch("s10", cls=cls, protocols=OF_PROTOL)
    s11 = net.addSwitch("s11", cls=cls, protocols=OF_PROTOL)
    s13 = net.addSwitch("s13", cls=cls, protocols=OF_PROTOL)
    s14 = net.addSwitch("s14", cls=cls, protocols=OF_PROTOL)
    s15 = net.addSwitch("s15", cls=cls, protocols=OF_PROTOL)

    # ############################################
    #               Links
    # ############################################
    logger.info("Creating links")

    net.addLink(s3, s1, bw=BW_CORE_TO_CORE)  # BW [Mbits / s]
    net.addLink(s3, s2, bw=BW_CORE_TO_CORE)

    net.addLink(s2, s1, bw=BW_CORE_TO_CORE)  # BW [Mbits / s]

    net.addLink(s5, s4, bw=BW_DISTRIBUTION_TO_DISTRIBUTION)
    net.addLink(s1, s5, bw=BW_CORE_TO_DISTRIBUTION)
    net.addLink(s2, s5, bw=BW_CORE_TO_DISTRIBUTION)
    net.addLink(s1, s4, bw=BW_CORE_TO_DISTRIBUTION)
    net.addLink(s2, s4, bw=BW_CORE_TO_DISTRIBUTION)

    net.addLink(s6, s7, bw=BW_DISTRIBUTION_TO_DISTRIBUTION)
    net.addLink(s1, s7, bw=BW_CORE_TO_DISTRIBUTION)
    net.addLink(s2, s7, bw=BW_CORE_TO_DISTRIBUTION)
    net.addLink(s1, s6, bw=BW_CORE_TO_DISTRIBUTION)
    net.addLink(s2, s6, bw=BW_CORE_TO_DISTRIBUTION)

    net.addLink(s8, s4, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s9, s4, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s10, s4, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s11, s4, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s8, s5, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s9, s5, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s10, s5, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s11, s5, bw=BW_DISTRIBUTION_TO_EDGE)

    net.addLink(s12, s6, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s13, s6, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s14, s6, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s15, s6, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s12, s7, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s13, s7, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s14, s7, bw=BW_DISTRIBUTION_TO_EDGE)
    net.addLink(s15, s7, bw=BW_DISTRIBUTION_TO_EDGE)

    net.addLink(vict[0], s8, bw=BW_SERVER)
    net.addLink(vict[1], s12, bw=BW_SERVER)
    net.addLink(vict[2], s12, bw=BW_SERVER)  # Corregir archivo snort.conf"""

    net.addLink(ids[0], s4, bw=BW_IDS)
    net.addLink(ids[1], s5, bw=BW_IDS)
    net.addLink(ids[2], s6, bw=BW_IDS)
    net.addLink(ids[3], s7, bw=BW_IDS)

    net.addLink(bots[0], s9, bw=BW_CLIENT)
    net.addLink(bots[1], s10, bw=BW_CLIENT)
    net.addLink(bots[2], s11, bw=BW_CLIENT)
    net.addLink(bots[3], s13, bw=BW_CLIENT)
    net.addLink(bots[4], s14, bw=BW_CLIENT)
    net.addLink(bots[5], s15, bw=BW_CLIENT)

    net.addLink(bots[6], s10, bw=BW_CLIENT)
    net.addLink(bots[7], s14, bw=BW_CLIENT)

    net.addLink(users[0], s9, bw=BW_CLIENT)
    net.addLink(users[1], s9, bw=BW_CLIENT)
    net.addLink(users[2], s10, bw=BW_CLIENT)
    net.addLink(users[3], s10, bw=BW_CLIENT)
    net.addLink(users[4], s11, bw=BW_CLIENT)
    net.addLink(users[5], s11, bw=BW_CLIENT)
    net.addLink(users[6], s13, bw=BW_CLIENT)
    net.addLink(users[7], s13, bw=BW_CLIENT)
    net.addLink(users[8], s14, bw=BW_CLIENT)
    net.addLink(users[9], s14, bw=BW_CLIENT)
    net.addLink(users[10], s15, bw=BW_CLIENT)
    net.addLink(users[11], s15, bw=BW_CLIENT)

    # ############################################
    #        Conatainers Comands
    # ############################################

    for i in range(users.__len__()):
        users[i].cmd("ip route add 192.168.0.0/16 dev user_leg" + str(i) + "-eth0")
    for i in range(bots.__len__()):
        bots[i].cmd("ip route add 192.168.0.0/16 dev bot" + str(i) + "-eth0")

    for i in range(ids.__len__()):
        ids[i].cmd("ip route add 192.168.0.0/16 dev ids" + str(i + 1) + "-eth0")
    for i in range(vict.__len__()):
        vict[i].cmd("ip route add 192.168.0.0/16 dev vict" + str(i) + "-eth0")

    # ############################################
    #        START NETWORK
    # ############################################

    logger.info("Starting network")
    net.start()

    # Run httpd-foreground command
    for i in range(vict.__len__()):
        vict[i].start()
    # Run Snort Sniffer
    for i in range(ids.__len__()):
        ids[i].start()

    logger.info("Testing connectivity")
    net.pingAll()

    # Run init Cmd
    for i in range(users.__len__()):
        users[i].start()

    logger.info("Running CLI")
    CLI(net)

    # ############################################
    #               END
    # ############################################

    logger.info("Stopping network")
    net.stop()


if __name__ == "__main__":
    """
    Main
    """

    topoloy()
    exit(0)
