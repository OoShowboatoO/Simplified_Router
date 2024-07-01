#include "router.hh"

#include <iostream>
#include <limits>

using namespace std;

// route_prefix: The "up-to-32-bit" IPv4 address prefix to match the datagram's destination address against
// prefix_length: For this route to be applicable, how many high-order (most-significant) bits of
//    the route_prefix will need to match the corresponding bits of the datagram's destination address?
// next_hop: The IP address of the next hop. Will be empty if the network is directly attached to the router (in
//    which case, the next hop address should be the datagram's final destination).
// interface_num: The index of the interface to send the datagram out on.
void Router::add_route( const uint32_t route_prefix,
                        const uint8_t prefix_length,
                        const optional<Address> next_hop,
                        const size_t interface_num )
{
  cerr << "DEBUG: adding route " << Address::from_ipv4_numeric( route_prefix ).ip() << "/"
       << static_cast<int>( prefix_length ) << " => " << ( next_hop.has_value() ? next_hop->ip() : "(direct)" )
       << " on interface " << interface_num << "\n";

  // Construct a routing tabke element
  RoutingTableElement r_element(route_prefix, prefix_length, next_hop, interface_num);
  
  // Add the element into the routing table
  routing_table_.push_back(r_element);
}


void Router::route_single_dgram(InternetDatagram &dgram){
  int target_index = -1;
  int longest_prefix_len = -1;
  
  // Check TTL field, if <= 0, then drop the packet
  if ( dgram.header.ttl <= 0 )
    return;

  // Find the best route
  uint32_t dest = dgram.header.dst;
  for ( size_t i = 0; i < routing_table_.size(); i++ ) {   
    // Using bitmask to figure out how many bits we need to isolate
    uint32_t bitmask = 0;
    if (routing_table_[i].prefix_length_ > 0 && routing_table_[i].prefix_length_<= 32) {
      bitmask = numeric_limits<int>::min() >> (routing_table_[i].prefix_length_ - 1);
    }
    
    // Using bitwise AND operation to get a target prefix comparing with route_prefix
    uint32_t target_prefix = bitmask & dest;
    if (target_prefix == routing_table_[i].route_prefix_ && longest_prefix_len <= routing_table_[i].prefix_length_) {
      longest_prefix_len = routing_table_[i].prefix_length_;
      target_index = i;
    }
  }

  // If there is no matching route for a packet, drop the packet 
  if ( target_index == -1 )
    return;

  // Decrementing the TTL field, and check if TTL becomes to 0.
  dgram.header.ttl -= 1;
  if (dgram.header.ttl <= 0) {
    return;
  }
  dgram.header.compute_checksum();

  // The packet should be sent out on the interface that is specified in the route.
  size_t target_interface = routing_table_[target_index].interface_num_;
  optional<Address> next_hop = routing_table_[target_index].next_hop_;
  
  // Check if the packet needs to be sent to another router
  if (next_hop.has_value()) {
    interfaces_[target_interface].send_datagram( dgram, next_hop.value() );
  } else {
    interfaces_[target_interface].send_datagram( dgram, Address::from_ipv4_numeric(dest) );
  }
}

void Router::route() {
  for (auto& this_interface : interfaces_ ) {
    optional<InternetDatagram> this_datagram = this_interface.maybe_receive();
    while (this_datagram.has_value()) {
      route_single_dgram(this_datagram.value());
      this_datagram = this_interface.maybe_receive();
    }
  }
}
