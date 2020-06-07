import logging
import pickle
import select
import socket
import sys
from signal import signal, SIGINT
from sys import exit

logging.getLogger().setLevel(logging.INFO)


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

        # the sockets you can write to
        self.write_sockets = []

        # error sockets
        self.error_sockets = []

        # end general management -----------------------------------------------------------

    # get local ip address
    def get_IP(self):
        return socket.gethostbyname(socket.gethostname())

    # exit the tor server - disconnect and send exit to all
    def exit_tor(self):
        # send EXIT as a broadcast
        self.send_broadcast("EXIT")
        # close the socket
        self.for_servers_socket.close()

    # at start broadcast to all that im here
    def connection_birth(self):
        msg = "SYN"
        # broadcast SYN to all tor_servers'
        self.send_broadcast(msg)
        # if not in server_connection_list; append and add t list
        if self.server_address not in self.server_connection_list:
            self.server_connection_list.append(self.server_address)
            # prints the tor_servers' currently active
            print "tor_servers:", self.server_connection_list

    # if receive exit remove from list
    def handle_EXIT(self, addr):
        # checks if it was even in the list
        if addr in self.server_connection_list:
            print "removing " + str(addr)
            # removing from list
            self.server_connection_list.remove(addr)
            print "tor_servers:", self.server_connection_list

    # checks if addr is in the server_connection_list; if isn't adds it to list and prints the new list
    def add_to_list(self, addr):
        if addr not in self.server_connection_list:
            self.server_connection_list.append(addr)
        print "tor_servers:", self.server_connection_list

    # handle the handshake
    def handle_SYN_ACK(self, data, addr):
        if data == "SYN":
            # checks to see if it wasn't a msg sent to self
            if addr != self.server_address:
                self.for_servers_socket.sendto("SYN / ACK", addr)
                # checks if addr is in the server_connection_list; if isn't adds it to list
                self.add_to_list(addr)
        elif data == "SYN / ACK":
            # checks if addr is in the server_connection_list; if isn't adds it to list
            self.add_to_list(addr)
            # send ACK to the sender
            self.for_servers_socket.sendto("ACK", addr)
        elif data == "ACK":
            # checks if addr is in the server_connection_list; if isn't adds it to list
            self.add_to_list(addr)
        else:
            # this means that the handshake failed
            print "HANDSHAKE FAILED"

    # broadcast a wanted msg to all tor_servers'
    def send_broadcast(self, msg):
        self.for_servers_socket.sendto(msg, ('<broadcast>', 2000))

    # handle SIGINT
    def handler(self, signal_received, frame):
        print('SIGINT or CTRL-C detected. Exiting gracefully')
        # sends EXIT to all tor_servers' and closes the socket
        self.exit_tor()
        # exit gracefully
        exit(0)

    # if a client is forced to exit removes him from the read_sockets' and adds him to the error_sockets'
    def forced_exit_client(self, socket):
        self.read_sockets.remove(socket)
        self.error_sockets.append(socket)

    # extracts the onion when the msg starts with TO_FORWARD
    def get_onion(self, data):
        # finds the exact location of the byte_onion
        byte_onion_start = data.find("ONION") + len("ONION") + 1
        byte_onion_end = data.find("REVERSE_ONION")
        byte_onion = data[byte_onion_start:byte_onion_end]
        # loads the onion to an object instead of the bit presentation
        onion = pickle.loads(byte_onion)
        print "onion is: " + str(onion) + " type is: " + str(type(onion))
        return onion

    # extracts the reverse_onion when the msg starts with TO_FORWARD
    def get_reverse_onion(self, data):
        # finds the exact location of the byte_reverse_onion_start
        byte_reverse_onion_start = data.find("REVERSE_ONION") + len("REVERSE_ONION") + 1
        byte_reverse_onion = data[byte_reverse_onion_start:]
        # loads the reverse_onion to an object instead of the bit presentation
        reverse_onion = pickle.loads(byte_reverse_onion)
        return reverse_onion

    # extracts the msg when the msg starts with TO_FORWARD
    def get_msg(self, data):
        # finds the exact location of the msg
        msg_start = data.find("MSG") + len("MSG") + 1
        msg_end = data.find("ONION")
        msg = data[msg_start:msg_end]
        return msg

    # sends data to client
    def send_to_client(self, data):
        logging.info("sending to client")
        # get the wanted msg to send to the client
        msg = self.get_msg(data)
        logging.info("msg: " + msg)
        # sends the message to the connected client
        self.for_clients_socket.send(msg)
        print "sent to client"

    # forwards a msg to another tor_server or the the hidden_client
    def forward_msg(self, data):
        # gets the onion
        onion = self.get_onion(data)
        # checks if onion is received as list (only happens when it needs to be sent to hidden_client afterwards)
        if type(onion) is type([]):
            if len(onion) > 1:
                # if in this segment it means that the next destination is the hidden_client
                destination = onion[0]
                onion = []
            else:
                destination = None
        # else acts as if onion is an object
        else:
            # get the destination to send to
            destination = onion.get_layer_destination_address()
            logging.info("next destination is: " + str(destination))
            # peels a layer of the onion
            onion = onion.peel_layer()
            logging.info("now onion is: " + str(onion))
        # if destination is None it is sent to hidden_client
        if destination is None:
            self.send_to_client(data)
            return
        # gets the reverse_onion
        reverse_onion = self.get_reverse_onion(data)

        # pickle dump - makes the objects in bit presentation
        byte_onion = pickle.dumps(onion)
        byte_reverse_onion = pickle.dumps(reverse_onion)
        # gets the msg from the data
        msg = self.get_msg(data)
        # makes the message to forward on
        data = "TO_FORWARD:" + "MSG:" + msg + "ONION:" + byte_onion + "REVERSE_ONION:" + byte_reverse_onion

        logging.info("data is:" + data)
        # sends the message to next in line
        self.for_servers_socket.sendto(data, destination)

    # receives and handles data
    def recv_data(self):
        # selects which socket is used
        rlist, wlist, xlist = select.select(self.read_sockets, self.write_sockets, self.error_sockets)
        for read_socket in rlist:
            # if the socket is a for_servers_socket it means the message is from a tor_server
            if read_socket == self.for_servers_socket:
                try:
                    # receives the data and the addr from which it was sent
                    server_data, server_addr = self.for_servers_socket.recvfrom(self.BUFFER)
                    logging.info("msg is: " + server_data + ", sender is a tor_server from " + str(server_addr))
                    # if there is a SYN or an ACK in the data it is sent to the SYN_ACK handler
                    if "SYN" in server_data or "ACK" in server_data:
                        self.handle_SYN_ACK(server_data, server_addr)
                    # if the data is EXIT it is sent to the EXIT handler
                    elif server_data == "EXIT":
                        self.handle_EXIT(server_addr)
                    # if the data starts with TO_FORWARD it is send to the forward_msg function which handles a message
                    # that needs to be forwarded
                    elif "TO_FORWARD" in server_data:
                        self.forward_msg(server_data)
                    else:
                        pass
                except socket.error:
                    # if there is an error it means the socket is down and we can't continue, it closes the program
                    print "server socket dead... going down"
                    sys.exit(0)
            # if the socket is a for_clients_socket it means the message is from a hidden_client and it needs to be
            # accepted
            elif read_socket == self.for_clients_socket:
                client_socket, client_address = self.for_clients_socket.accept()
                # receives the new client socket and the clients address
                logging.info("new client from: " + str(client_address) + ", socket is: " + str(client_socket))
                # if the socket is not in the read_sockets' it is appended to the list
                if client_socket not in self.read_sockets:
                    self.read_sockets.append(client_socket)
                print "client connected from:", client_address
            # if none of the above were true it means that the socket is an existing one and it means that it's a
            # message from the hidden_client
            else:  # client_socket
                try:
                    # receives the data from the hidden_client
                    data = read_socket.recv(self.BUFFER)
                    logging.info("msg is: " + data + ", sender is a hidden_client")
                    # if the data is GIVE_LIVE_SERVERS it returns all the live tor_servers to the hidden_client
                    if data == 'GIVE_LIVE_SERVERS':
                        # builds the message to return to hidden_client
                        msg = "LIVE_SERVERS:", self.server_connection_list
                        # sends the message
                        read_socket.send(str(msg))
                    # if the data has TO_FORWARD in it, it is sent to the forward_msg handler
                    elif "TO_FORWARD" in data:
                        self.forward_msg(data)
                    else:
                        # else it means that the message was received but is undefined so it returns that
                        read_socket.send('received msg but undefined')
                except socket.error:
                    # if there is an error it is sent to forced_exit_client handler
                    self.forced_exit_client(read_socket)

    # how the server is run
    def run_server(self):
        # handle ctrl+c - exits gracefully
        signal(SIGINT, self.handler)
        # sends SYN to all tor_servers alive
        self.connection_birth()
        # while the server runs it enters the recv_data function infinitly
        while True:
            self.recv_data()


# starts the server
if __name__ == '__main__':
    server = tor_server()
    server.run_server()
