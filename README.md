# Simplified_Router

The project contains a simplified networking stack for hosts and a simplified routing that performs the fundamental task of a router.\
The implementation of simplified networking stack take care of encapsulating Datagram packets inside appropriate IP and Ethernet packets and perform necessary tasks such as sending ARP requests and replying back to ARP requests.\
The implementation of simplified router perform the fundamental task of a router: determining the next hop of packet in its journey to the destination host. This includes finding the best route for the packet from the routes installed in the routing table.