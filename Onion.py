class Onion(object):
    # init variables
    def __init__(self):
        # how many layers does the onion have - starts with 0
        self.layer_count = 0
        # data in the onion - stores addresses
        self.data = []

    # peels a layer from the onion
    def peel_layer(self):
        # if there is more than 0 layers it can peel
        if self.layer_count > 0:
            # decrease layer count
            self.layer_count -= 1
            # remove the outer most onion layer - removes the first address from the onion
            destination = self.data[0]
            self.data.remove(destination)
            return self.data
        # if there are no addresses stored return None
        else:
            print "return none"
            return None

    # get the next address in the onion
    def get_layer_destination_address(self):
        # if there are 1 or more addresses stored it returns the next address
        if len(self.data) >= 1:
            destination = self.data[0]
            return destination
        # otherwise it means that there are no more addresses and the onion is empty
        else:
            # return None
            return None

    # this adds a layer for the onion
    def add_layer_for_onion(self, destination):
        # if there aren't at least 2 layers on the onion it can add a layer
        if self.layer_count < 2:
            # adds a layer to the onion - appends the address
            self.data.append(destination)
            # increases the layer count
            self.layer_count += 1
            return self.data
        # if there are more than 2 there is no way to add a new layer so returns None
        else:
            return None

    # this adds a layer for the reverse onion
    def add_layer_for_reverse_onion(self, destination):
        # if there aren't at least 3 layers on the onion it can add a layer
        if self.layer_count < 3:
            # adds a layer to the reverse onion - appends the address
            self.data.append(destination)
            # increases the layer count
            self.layer_count += 1
            return self.data
        # if there are more than 3 there is no way to add a new layer so returns None
        else:
            return None

    # returns the number of layers the onion currently has
    def get_layer_count(self):
        return self.layer_count

    # returns a list with all the addresses the onion is storing
    def get_data(self):
        return self.data

    # builds the onion from scratch
    def build_onion(self, running_list):
        # runs on all the alive tor_servers' list and appends the addresses
        for server in running_list:
            self.add_layer_for_onion(server)
        # returns the complete onion
        return self.data

    # builds the reverse onion from scratch
    def build_reverse_onion(self, running_list):
        # reverses the alive tor_servers list
        running_list.reverse()
        # runs on all the reversed alive tor_servers' list and appends the addresses
        for server in running_list:
            self.add_layer_for_reverse_onion(server)
        # returns the complete reverse onion
        return self.data
