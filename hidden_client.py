import random
import select
import socket
import ast
from Onion import Onion
import pickle


class hidden_client(object):
    def __init__(self):

        # socket setup--------------------------------------------------------------

        # client socket that will be connected to a tor_server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # client ip address
        self.IP = self.get_IP()

        # client port
        self.port = 2500

        # client address
        self.address = (self.IP, self.port)

        # connects the socket to the address
        self.socket.connect(self.address)

        # end socket setup--------------------------------------------------------------

        # others----------------------------------------------------

        # a list of all running tor_servers - will be appended when client is run
        self.running_servers_list = []

        # all sockets that abruptly closed - error sockets
        self.error_sockets = []

        # end others -- - - - - - --------------------------------------------------

    # get local ip address
    def get_IP(self):
        return socket.gethostbyname(socket.gethostname())

    # gets all the alive tor_servers
    def get_all_running_tor_servers(self):
        # sends to the connected tor_server to give all the live tor_servers
        self.socket.send('GIVE_LIVE_SERVERS')
        # receives the data from the tor_server and stores the list of running tor_servers
        self.running_servers_list = self.receive_data()

    # handles when data is received from a tor_server
    def receive_data(self):
        try:
            # receives the data from the tor_server
            data = self.socket.recv(1024)
            # if the data has LIVE_SERVERS in it; it is a list of all alive tor_servers
            if "LIVE_SERVERS:" in data:
                # finds the place of the tor_servers
                start_of_msg = len("LIVE_SERVERS:") + 5
                end_of_msg = len(data)
                running_list = data[start_of_msg:end_of_msg - 1]
                # makes the data into a list
                running_list = ast.literal_eval(running_list)
                # returns the alive tor_servers as a list
                return running_list
            # if the data is LESS_THAN_3_LIVE_SERVERS it means that there aren't sufficient tor_servers for the
            # algorithm to work and it returns None
            elif "LESS_THAN_3_LIVE_SERVERS" == data:
                return None
            # otherwise it returns the data
            else:
                return data
        # otherwise the socket is damaged and the connection needs to be closed
        except socket.error:
            # exits gracefully
            self.socket.close()
            exit(0)

    # builds the route for the packet that will be sent to the other hidden_client
    def build_packet_route(self, last_addr):
        # gets the list of all alive tor_servers'
        running_list = self.running_servers_list[:]
        # if the length of the list is 3 or more it can be built
        if len(running_list) >= 3:
            # appends the addresses of 3 running tor_servers' to the list
            list = [running_list[0]]
            running_list.remove(last_addr)
            list.append(random.choice(running_list[1:]))
            # finally appends the last address that is wanted
            list.append(last_addr)

            # builds the onion
            onion = Onion()
            onion.build_onion(list[1:])
            print "onion:", onion.get_data()

            # build reverse onion for coming back from hidden_client
            reverse_onion = Onion()
            reverse_onion.build_reverse_onion(list)
            print "reverse_onion:", reverse_onion.get_data()

            # sends a message to the other hidden_client; goes through 3 tor_servers' first
            self.send_msg("hi man", onion, reverse_onion)

    # sends a message to the first tor_server in the onion
    def send_msg(self, msg, onion, reverse_onion):
        # dump the onion and reverse onion into bits so it can be transferred via the socket
        byte_onion = pickle.dumps(onion)
        byte_reverse_onion = pickle.dumps(reverse_onion)
        # builds the message that will be sent
        data = "TO_FORWARD:" + "MSG:" + msg + "ONION:" + byte_onion + "REVERSE_ONION:" + byte_reverse_onion
        # sends the message to first tor_server in onion
        self.socket.send(data)

    # this runs the hidden_client
    def run_hidden_client(self):
        # loops infinitely
        while True:
            # gets all alive tor_servers
            self.get_all_running_tor_servers()
            # select function to handle all sockets connected to hidden_client
            rlist, wlist, xlist = select.select([self.socket], [self.socket], [self.socket])
            # if the socket is in rlist it can receive data
            for read_socket in rlist:
                try:
                    # get msg from the tor_server
                    msg = read_socket.recv(1024)
                    # prints it
                    print msg
                except socket.error:
                    pass
            # the options for the user
            print "1 - get running tor server list \n" \
                  "2 - build a route to send packet \n"
            # gets the input
            info = raw_input()
            # this prints the alive tor_servers
            if info == '1':
                print self.running_servers_list
            # this sends a message to another hidden_client
            if info == '2':
                print "pick where to send - the most left is 1 and it goes upwards"
                print self.running_servers_list[1:]
                # gets which hidden_client to send to
                ans = raw_input()
                # builds the route and sends to first tor_server - outermost onion layer
                self.build_packet_route(self.running_servers_list[int(ans)])


# main function - starts the program
if __name__ == '__main__':
    client = hidden_client()
    client.run_hidden_client()
