
class Onion(object):
    def __init__(self):
        self.layer_count = 0
        self.data = []

    def peel_layer(self):
        if self.layer_count > 0:
            self.layer_count -= 1
            destination = self.data[0]
            self.data.remove(destination)
            return self.data
        else:
            print "return none"
            return None

    def get_layer_destination_address(self):
        if len(self.data) >= 1:
            destination = self.data[0]
            return destination
        else:
            return None

    def add_layer1(self, destination):
        if self.layer_count < 2:
            self.data.append(destination)
            self.layer_count += 1
            return self.data
        else:
            return None

    def add_layer2(self, destination):
        if self.layer_count < 3:
            self.data.append(destination)
            self.layer_count += 1
            return self.data
        else:
            return None

    def get_layer_count(self):
        return self.layer_count

    def get_data(self):
        return self.data

    def build_onion(self, running_list):
        for server in running_list:
            self.add_layer1(server)
        return self.data

    def build_reverse_onion(self, running_list):
        running_list.reverse()
        for server in running_list:
            self.add_layer2(server)
        return self.data
