#include "network_interface.hh"

#include "arp_message.hh"
#include "ethernet_frame.hh"

using namespace std;

size_t curr_time = 0;

// ethernet_address: Ethernet (what ARP calls "hardware") address of the interface
// ip_address: IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address )
  : ethernet_address_( ethernet_address ), ip_address_( ip_address )
{
  cerr << "DEBUG: Network interface has Ethernet address " << to_string( ethernet_address_ ) << " and IP address "
       << ip_address.ip() << "\n";
}

// Helper: return a ARP message according to 5 parameters
ARPMessage NetworkInterface::make_arp_message(const EthernetAddress sender_ethernet_address, const uint32_t& sender_ip_address, 
                            const EthernetAddress target_ethernet_address, const uint32_t& target_ip_address, 
                            const uint16_t opcode) 
{
  ARPMessage APR_message;
  APR_message.sender_ip_address = sender_ip_address;
  APR_message.sender_ethernet_address = sender_ethernet_address;
  APR_message.target_ip_address = target_ip_address;
  APR_message.target_ethernet_address = target_ethernet_address;
  APR_message.opcode = opcode;

  return APR_message;
}


// Helper: return an ethernet frame according to 4 parameters
EthernetFrame NetworkInterface::make_ethernet_frame(const EthernetAddress& dst, const EthernetAddress& src, 
                                  const uint16_t type, vector<Buffer> payload)
{
  EthernetFrame frame;
  frame.header.dst = dst;
  frame.header.src = src;
  frame.header.type = type;
  frame.payload = std::move( payload );
  
  return frame;
}

// dgram: the IPv4 datagram to be sent
// next_hop: the IP address of the interface to send it to (typically a router or default gateway, but
// may also be another host if directly connected to the same network as the destination)

// Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) by using the
// Address::ipv4_numeric() method.
void NetworkInterface::send_datagram( const InternetDatagram& dgram, const Address& next_hop )
{
  const uint32_t next_hop_ip = next_hop.ipv4_numeric();

  // Check if we know the MAC address in the ARP Table
  bool found_ip = (ARP_table.find(next_hop_ip) != ARP_table.end());
  
  if (found_ip) {
    // MAC address is found
    // Create an Ethernet frame, and initialize Ethernet frame
    auto target = ARP_table.find(next_hop_ip);
    const EthernetAddress target_mac_addr = target->second.MAC_addr;
    EthernetFrame ether_frame = make_ethernet_frame(target_mac_addr, ethernet_address_, 
                                                    EthernetHeader::TYPE_IPv4, serialize(dgram));

    // put it in the ready-to-be-sent queue
    ready2_sent_q.push(ether_frame); 
  } else {
    // MAC address is NOT found
    // Check if the ARP request is sent before
    bool found_request = (request_history.find(next_hop_ip) != request_history.end());

    // Create a ARP request frame
    // First, create an ARP request message
    ARPMessage APR_request_message = make_arp_message(ethernet_address_, ip_address_.ipv4_numeric(), 
                                                      {}, next_hop.ipv4_numeric(), ARPMessage::OPCODE_REQUEST);

    // Second, put the ARP request message in an EthernetFrame
    EthernetFrame ARP_request_frame = make_ethernet_frame(ETHERNET_BROADCAST, ethernet_address_, 
                                                          EthernetHeader::TYPE_ARP, serialize(APR_request_message));

    // Create a Ethernet frame without MAC addr, and push it in the waiting queue later
    EthernetFrame ether_frame_no_MAC = make_ethernet_frame({}, ethernet_address_, EthernetHeader::TYPE_IPv4, serialize(dgram));

    if (!found_request) {
      // if the request is NOT sent before
      request_history[next_hop.ipv4_numeric()] = curr_time; 
      ready2_sent_q.push(ARP_request_frame);
    } else if (found_request && (curr_time - request_history[next_hop.ipv4_numeric()] < NetworkInterface::MAX_WAITING_TIME)) {
      // if the request is sent in the last 5 seconds
      Waiting_Packet request_waiting_packet = Waiting_Packet{next_hop.ipv4_numeric(), ARP_request_frame, SIZE_MAX};
      waiting_q.push(request_waiting_packet);
    } else {
      // if the request is sent, but not in the last 5 seconds
      request_history[next_hop.ipv4_numeric()] = curr_time;
      ready2_sent_q.push(ARP_request_frame);
    }
    
    //Push the thernet frame without MAC addr in the waiting queue
    Waiting_Packet packet_no_MAC = Waiting_Packet{next_hop.ipv4_numeric(), ether_frame_no_MAC, curr_time};
    waiting_q.push(packet_no_MAC);
  }

}


// frame: the incoming Ethernet frame
optional<InternetDatagram> NetworkInterface::recv_frame( const EthernetFrame& frame )
{
  optional<InternetDatagram> res = nullopt;
  // If this packet is destined to this machine and its payload an IPv4 packet
  if (frame.header.dst == ethernet_address_ && frame.header.type == EthernetHeader::TYPE_IPv4) {
    InternetDatagram dgram;
    if (parse(dgram, frame.payload)) {
      res = dgram;
    }
  } else if ((frame.header.dst == ethernet_address_ && frame.header.type == EthernetHeader::TYPE_ARP) || 
              (frame.header.dst == ETHERNET_BROADCAST && frame.header.type == EthernetHeader::TYPE_ARP)){
    // If this packet is destined to this machine and its payload an ARP packet
    ARPMessage arp_message;
    if (parse(arp_message, frame.payload)) {
      // learn the mapping between the packet’s Sender IP address and its MAC address and cache this in the ARP cache table
      uint32_t sender_ip = arp_message.sender_ip_address;
      const EthernetAddress sender_mac_addr = arp_message.sender_ethernet_address;
      Ether_Addr_Entry sender_ether_addr_entry = Ether_Addr_Entry{arp_message.sender_ethernet_address, curr_time};
      ARP_table[sender_ip] = sender_ether_addr_entry;

      // if it is an ARP request that asks for our IP address, reply back to it.
      if (arp_message.opcode == ARPMessage::OPCODE_REQUEST && ip_address_.ipv4_numeric() == arp_message.target_ip_address) {
        // Create an ARP reply message and initialize
        ARPMessage ARP_reply_message = make_arp_message(ethernet_address_, ip_address_.ipv4_numeric(), 
                                                        sender_mac_addr, sender_ip, ARPMessage::OPCODE_REPLY);

        // Create an Ethernet frame to reply and put the ARP reply message in the reply_frame
        EthernetFrame ARP_reply_frame = make_ethernet_frame(sender_mac_addr, ethernet_address_, 
                                                            EthernetHeader::TYPE_ARP, serialize(ARP_reply_message));

        // put it in the ready-to-be-sent queue
        ready2_sent_q.push(ARP_reply_frame); 
      } else if (arp_message.opcode == ARPMessage::OPCODE_REPLY && ip_address_.ipv4_numeric() == arp_message.target_ip_address) {
        // if it is an ARP reply message, then update the waiting queue according to the ARP reply message
        //  Idea to remove element from queue is from ChatGPT
        std::queue<Waiting_Packet> temp_q = std::queue<Waiting_Packet>();
        while(!waiting_q.empty()) {
          Waiting_Packet curr_first = waiting_q.front();
          uint16_t first_frame_type = curr_first.waiting_frame.header.type;
          if (sender_ip != curr_first.dst_ip) {
            temp_q.push(curr_first);
          } else if (sender_ip == curr_first.dst_ip && first_frame_type == EthernetHeader::TYPE_IPv4) {
            // Update the Ipv4 packet and move it from waiting queue to the ready-to-be-sent queue
            EthernetFrame curr_frame = curr_first.waiting_frame;
            curr_frame.header.dst = sender_mac_addr;
            ready2_sent_q.push(curr_frame);
          }
          waiting_q.pop();
        }
        // update the waiting queue
        waiting_q = temp_q;
      }
    }
    return res;
  }
  return res;
}


// ms_since_last_tick: the number of milliseconds since the last call to this method
void NetworkInterface::tick( const size_t ms_since_last_tick )
{
  // Update current time
  curr_time += ms_since_last_tick;
  std::queue<uint32_t> expired_ip = queue<uint32_t>();
  // Expire any entry in ARP cache table that was learnt more than 30 seconds ago
  for(auto it = ARP_table.begin(); it != ARP_table.end(); it++) {
    if (curr_time - it->second.caching_time > NetworkInterface::MAX_CACHE_TIME) {
      uint32_t this_ip = it->first;
      expired_ip.push(this_ip);
    }
  }
  // Update ARP_table accordingly
  while(!expired_ip.empty()) {
    uint32_t discard_ip = expired_ip.front();
    ARP_table.erase(discard_ip);
    expired_ip.pop();
  }

  // update the waiting queue
  std::queue<Waiting_Packet> temp_q = std::queue<Waiting_Packet>();
  while(!waiting_q.empty()) {
    Waiting_Packet curr_first = waiting_q.front();
    uint16_t first_frame_type = curr_first.waiting_frame.header.type;
    uint32_t first_ip = curr_first.dst_ip;
    size_t ARP_caching_time = request_history[first_ip];
    if (curr_time - ARP_caching_time >= NetworkInterface::MAX_WAITING_TIME && 
        first_frame_type == EthernetHeader::TYPE_ARP &&
        curr_first.waiting_frame.header.dst == ETHERNET_BROADCAST) {
      // update request time to the new current calue
      request_history[first_ip] = curr_time;
      // Move the ARP request to the ready-to-be-sent queue; otherwise, there will be no ARP request to get the MAC addr
      EthernetFrame resend_ARP_request_packet = curr_first.waiting_frame;
      ready2_sent_q.push(resend_ARP_request_packet);
    } else if ((curr_first.waiting_frame.header.type == EthernetHeader::TYPE_IPv4) || 
              (curr_time - curr_first.time < NetworkInterface::MAX_WAITING_TIME)) {
      temp_q.push(curr_first);
    }
    waiting_q.pop();
  }
  // Only keep the Waiting_Packet without MAC address and the Waiting_Packet with valid ARP message
  waiting_q = temp_q;
}


optional<EthernetFrame> NetworkInterface::maybe_send()
{
  // Check if ready-to-be-sent queue is empty
  if (!ready2_sent_q.empty()) {
    // send out the first element in the ready-to-be-sent queue
    EthernetFrame first_frame = ready2_sent_q.front();
    ready2_sent_q.pop();
    return first_frame;
  } else {
    return nullopt;
  }
}
