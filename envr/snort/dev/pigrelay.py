#!/usr/bin/python2
"""
Script send content from unixsock to inetsock
"""
import os
import sys
import time
import socket
import logging
import argparse
import signal
import netifaces
import json

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)
SOCKFILE = "/tmp/snort_alert"  # ubicacion del unix socket
BUFSIZE = 65863  # 1842
HAND_SIZE = 2
# Must to set your controller IP here
CONTROLLER_IP = '192.168.50.2'
# If you want to change the port number
# you need to set the same port number in the controller application.
CONTROLLER_PORT = 11991
NAME_IDS = ""


# TODO: TLS/SSL wrapper for socket
class SnortListener:

    def __init__(self, ip, port):
        self.unsock = None
        self.nwsock = None
        self.ip = ip
        self.port = port
        # add handler to close conex
        signal.signal(signal.SIGINT, self.hdlr_close)

    def start_send(self):
        """
        Open a client on Network Socket
        :return: none
        """

        self.nwsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.nwsock.connect((self.ip, self.port))
        except Exception:
            logger.error("Network socket connection error: %s")
            sys.exit(1)

    def start_recv(self):
        """
        Open a server on Unix Domain Socket
        :return: none
        """

        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.unsock.bind(SOCKFILE)
        logger.info("Unix Domain Socket listening...")
        self.recv_loop()

    def init_handshake(self):
        """
        Send all ips from host to Controller
        :return: void
        """
        dic = {"ips": []}  # create dictonary in order to send to controller
        interfaces = netifaces.interfaces()  # Get interfaces
        # Get Ipv4 addrs for every interface and put into dictonary
        for iface in interfaces:
            ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            dic["ips"].append(ip)
        dic["ips"].remove("127.0.0.1")  # delete if:lo

        json_data = json.dumps(dic)  # Create JSON node
        self.nwsock.sendall(json_data)

        while True:
            data = self.nwsock.recv(HAND_SIZE)  # block
            if data:
                return data

    def recv_loop(self):
        """
        Receive Snort alert on Unix Domain Socket and
        send to Network Socket Server forever
        :return: none
        """
        # Contador para estadisticas de alertas/segundo para local rules.
        contador_alertas = 0

        # Para medir alertas/segundo se necesita tiempo de inicio y tiempo de
        # fin.
        tiempo_inicio = 0
        tiempo_final = 0

        self.start_send()

        logger.info("Start the network socket client....")
        # Authentication
        if self.init_handshake() != 'OK':
            self.close_socket()
            logger.error("Authentication fail")
            return
        else:
            logger.info("Authentication success")

        flag_once = True
        while True:
            data = self.unsock.recv(BUFSIZE)
            if data:
                self.tcp_send(data)
            else:
                pass

    def tcp_send(self, data):
        """
        send data to controller
        :param data:
        :return:none
        """

        self.nwsock.sendall(data)
        logger.info("%s: Send alert messages to controller. (%d bytes)." %
                    (NAME_IDS, len(data)))

    def hdlr_close(self, signum, frame):
        """
        if detect SIGINT (Ctrl + c) handler to Close conection tcp
        :return: None
        """
        try:
            self.close_socket()
            logger.info("SIGINT, keyboard interrupt ")
            sys.exit(0)
        except Exception, e:
            logger.error("Network socket close error: %s" % e)
            sys.exit(1)

    def close_socket(self):
        try:
            self.nwsock.shutdown(socket.SHUT_RDWR)  # cierra la conexion tcp
            self.nwsock.close()  # cierra el objeto socket
        except Exception:
            self.nwsock.close()


if __name__ == '__main__':

    # definicion de argumentos
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ipaddr", default=CONTROLLER_IP,
                        help="direccion ip del controlador")
    parser.add_argument("-p", "--port", type=int, default=CONTROLLER_PORT,
                        help="numero de puerto del controlador")
    args = parser.parse_args()

    # Validate Ip
    if args.ipaddr:
        try:
            socket.inet_aton(args.ipaddr)  # Para validar la IP.
        except:
            args.ipaddr = CONTROLLER_IP
            logger.error("IP erronea. Se toma por defecto la IP %s" %
                         CONTROLLER_IP)
            logger.error("IP Controller: ", args.ipaddr)
            sys.exit(1)

    if (int(args.port) < 0) or (int(args.port) > 65535):
        logger.error("Error. Ingrese un numero de puerto valido.")
        sys.exit(1)

    NAME_IDS = socket.gethostname()
    # crete snortlistener object, unix -> tcp -> sdn controller
    server = SnortListener(args.ipaddr, args.port)
    # Start Send Alerts
    server.start_recv()
