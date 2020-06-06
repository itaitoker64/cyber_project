import socket
import sys
from signal import signal, SIGINT
from sys import exit
import select
import logging
import errno
from Onion import Onion
import pickle

logging.getLogger().setLevel(logging.INFO)


# class printble messages
# make private functions
# sequence number
# why udp with syn ack ack

class tor_server(object):
    def __init__(self):
        # get server ip address
        self.IP = self.get_IP()

        self.BUFFER = 4096

        # config server_socket -----------------------------------------------------------------------------------------
        self.for_servers_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP

        # self.for_servers_socket.setsockopt(socket.SOL_for_servers_socket, socket.SO_REUSEADDR, 1)

        # Enable broadcasting mode
        self.for_servers_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # the tor_server port
        self.server_port = 2000

        # the server address
        self.server_address = (self.IP, self.server_port)

        # bind the socket to the address
        self.for_servers_socket.bind(self.server_address)

        # end for_servers_socket config
        # -------------------------------------------------------------------------------------

        # config client socket -----------------------------------------------------------------------------------------
        self.for_clients_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # the client port
        self.client_port = 2500

        # the client address
        self.client_address = (self.IP, self.client_port)

        # bind the socket to the address
        self.for_clients_socket.bind(self.client_address)

        self.for_clients_socket.listen(5)

        # end client config --------------------------------------------------------------------------------------------
        # -----------------------------------------------------

        # start general management ----------------------------------------------------------------

        # a list of all server connections
        self.server_connection_list = []

        # the read list for the select
        self.read_sockets = [self.for_clients_socket, self.for_servers_socket]

        self.write_sockets = []

        self.error_sockets = []

        # end general management -----------------------------------------------------------

    # get local ip address
    def get_IP(self):
        return socket.gethostbyname(socket.gethostname())

    # exit the tor server - disconnect and send exit to all
    def exit_tor(self):
        self.send_broadcast("EXIT")
        self.for_servers_socket.close()

    # at start broadcast to all that im here
    def connection_birth(self):
        msg = "SYN"
        self.send_broadcast(msg)
        if self.server_address not in self.server_connection_list:
            self.server_connection_list.append(self.server_address)
            print "tor_servers:", self.server_connection_list

    # if receive exit remove from list
    def handle_EXIT(self, addr):
        if addr in self.server_connection_list:
            print "removing " + str(addr)
            self.server_connection_list.remove(addr)
            print "tor_servers:", self.server_connection_list

    # handle the handshake
    def handle_SYN_ACK(self, data, addr):
        if data == "SYN":
            if addr != self.server_address:
                self.for_servers_socket.sendto("SYN / ACK", addr)
                if addr not in self.server_connection_list:
                    self.server_connection_list.append(addr)
                print "tor_servers:", self.server_connection_list
        elif data == "SYN / ACK":
            if addr not in self.server_connection_list:
                self.server_connection_list.append(addr)
                print "tor_servers:", self.server_connection_list
            self.for_servers_socket.sendto("ACK", addr)
        elif data == "ACK":
            if addr not in self.server_connection_list:
                self.server_connection_list.append(addr)
                print "tor_servers:", self.server_connection_list
        else:
            print "HANDSHAKE FAILED"

    # broadcast to all
    def send_broadcast(self, msg):
        self.for_servers_socket.sendto(msg, ('<broadcast>', 2000))

    # handle SIGINT
    def handler(self, signal_received, frame):
        print('SIGINT or CTRL-C detected. Exiting gracefully')
        self.exit_tor()
        exit(0)

    def forced_exit_client(self, socket):
        self.read_sockets.remove(socket)
        self.error_sockets.append(socket)

    def get_onion(self, data):
        byte_onion_start = data.find("ONION") + len("ONION") + 1
        byte_onion_end = data.find("REVERSE_ONION")
        byte_onion = data[byte_onion_start:byte_onion_end]
        onion = pickle.loads(byte_onion)
        return onion

    def get_reverse_onion(self, data):
        byte_reverse_onion_start = data.find("REVERSE_ONION") + len("REVERSE_ONION") + 1
        byte_reverse_onion = data[byte_reverse_onion_start:]
        reverse_onion = pickle.loads(byte_reverse_onion)
        return reverse_onion

    def get_msg(self, data):
        msg_start = data.find("MSG") + len("MSG") + 1
        msg_end = data.find("ONION")
        msg = data[msg_start:msg_end]
        return msg

    def send_to_client(self, data):
        logging.info("sending to client")
        msg = self.get_msg(data)
        logging.info("msg: " + msg)
        self.for_clients_socket.send(msg)
        print "sent to client"

    def forward_msg(self, data):
        onion = self.get_onion(data)

        destination = onion.get_layer_destination_address()
        logging.info("next destination is: " +str(destination))
        if destination is None:
            self.send_to_client(data)
            return

        onion = onion.peel_layer()
        logging.info("now onion is: " + str(onion))

        reverse_onion = self.get_reverse_onion(data)

        # pickle dump
        byte_onion = pickle.dumps(onion)
        byte_reverse_onion = pickle.dumps(reverse_onion)

        msg = self.get_msg(data)

        data = "TO_FORWARD:" + "MSG:" + msg + "ONION:" + byte_onion + "REVERSE_ONION:" + byte_reverse_onion

        logging.info("data is:" + data)
        self.for_servers_socket.sendto(data, destination)

    def recv_data(self):
        rlist, wlist, xlist = select.select(self.read_sockets, self.write_sockets, self.error_sockets)
        for read_socket in rlist:
            if read_socket == self.for_servers_socket:
                try:
                    server_data, server_addr = self.for_servers_socket.recvfrom(self.BUFFER)
                    logging.info("msg is: " + server_data + ", sender is a tor_server from " + str(server_addr))
                    if "SYN" in server_data or "ACK" in server_data:
                        self.handle_SYN_ACK(server_data, server_addr)
                    elif server_data == "EXIT":
                        self.handle_EXIT(server_addr)
                    else:
                        pass
                except socket.error:
                    print "server socket dead... going down"
                    sys.exit(0)
            elif read_socket == self.for_clients_socket:
                client_socket, client_address = self.for_clients_socket.accept()
                logging.info("new client from: " + str(client_address) + ", socket is: " + str(client_socket))
                if client_socket not in self.read_sockets:
                    self.read_sockets.append(client_socket)
                print "client connected from:", client_address
            else:  # client_socket
                try:
                    data = read_socket.recv(self.BUFFER)
                    logging.info("msg is: " + data + ", sender is a hidden_client")
                    if data == 'GIVE_LIVE_SERVERS':
                        msg = "LIVE_SERVERS:", self.server_connection_list
                        read_socket.send(str(msg))
                    elif "TO_FORWARD" in data:
                        self.forward_msg(data)
                    else:
                        read_socket.send('received msg')
                except socket.error:
                    self.forced_exit_client(read_socket)

    def run_server(self):
        signal(SIGINT, self.handler)
        self.connection_birth()
        while True:
            self.recv_data()


if __name__ == '__main__':
    server = tor_server()
    server.run_server()
