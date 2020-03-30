import random
import select
import socket
import ast
from Onion import Onion
import pickle


class Proxy(object):
    min_onion_layers = 3

    def __init__(self):

        # socket setup--------------------------------------------------------------

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # IP = '10.51.101.92'
        self.IP = self.get_IP()

        self.port = 2500

        self.address = (self.IP, self.port)

        self.socket.connect(self.address)

        # end socket setup--------------------------------------------------------------

        # others----------------------------------------------------

        self.running_servers_list = []

        self.error_sockets = []

        # end others -- - - - - - --------------------------------------------------

    # get local ip address
    def get_IP(self):
        return socket.gethostbyname(socket.gethostname())

    def get_all_running_tor_servers(self):
        self.socket.send('GIVE_LIVE_SERVERS')
        self.running_servers_list = self.receive_data()

    def receive_data(self):
        try:
            data = self.socket.recv(1024)
            if "LIVE_SERVERS:" in data:
                start_of_msg = len("LIVE_SERVERS:") + 5
                end_of_msg = len(data)
                running_list = data[start_of_msg:end_of_msg - 1]
                running_list = ast.literal_eval(running_list)
                return running_list

            elif "LESS_THAN_3_LIVE_SERVERS" == data:
                return None
            else:
                return data
        except socket.error:
            print "here"

    def build_packet_route(self,last_addr):
        running_list = self.running_servers_list[:]
        if len(running_list) >= self.min_onion_layers:
            list = [running_list[0]]
            running_list.remove(last_addr)
            list.append(random.choice(running_list[1:]))
            list.append(last_addr)

            # build onion
            onion = Onion()
            onion.build_onion(list)
            print "onion:", onion.get_data()

            # build reverse onion for coming back
            reverse_onion = Onion()
            reverse_onion.build_reverse_onion(list)
            print "reverse_onion:", reverse_onion.get_data()

            self.send_msg("hi man",onion, reverse_onion)

    def send_msg(self, msg, onion, reverse_onion):
        byte_onion = pickle.dumps(onion)
        byte_reverse_onion = pickle.dumps(reverse_onion)

        data = "TO_FORWARD:" + "MSG:" + msg + "ONION:" + byte_onion + "REVERSE_ONION:" + byte_reverse_onion
        self.socket.send(data)

    def run_proxy(self):
        while True:
            self.get_all_running_tor_servers()
            rlist, wlist, xlist = select.select([self.socket], [self.socket], [self.socket])
            for read_socket in rlist:
                try:
                    msg = self.socket.recv(1024)
                    print msg
                except socket.error:
                    pass
            print "1 - get running tor server list \n" \
                  "2 - build a route to send packet \n" \
                  "3 - encrypt route \n" \
                  "4 - send packet"
            info = raw_input()
            if info == '1':
                print self.running_servers_list
            if info == '2':
                print "pick where to send"
                print self.running_servers_list[1:]
                ans = raw_input()
                self.build_packet_route(self.running_servers_list[int(ans)])




if __name__ == '__main__':
    proxy = Proxy()
    proxy.run_proxy()
