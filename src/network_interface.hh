#pragma once

#include "address.hh"
#include "ethernet_frame.hh"
#include "ipv4_datagram.hh"
#include "arp_message.hh"

#include <iostream>
#include <list>
#include <optional>
#include <queue>
#include <unordered_map>
#include <utility>
#include <map>

using namespace std;

// A "network interface" that connects IP (the internet layer, or network layer)
// with Ethernet (the network access layer, or link layer).

// This module is the lowest layer of a TCP/IP stack
// (connecting IP with the lower-layer network protocol,
// e.g. Ethernet). But the same module is also used repeatedly
// as part of a router: a router generally has many network
// interfaces, and the router's job is to route Internet datagrams
// between the different interfaces.

// The network interface translates datagrams (coming from the
// "customer," e.g. a TCP/IP stack or router) into Ethernet
// frames. To fill in the Ethernet destination address, it looks up
// the Ethernet address of the next IP hop of each datagram, making
// requests with the [Address Resolution Protocol](\ref rfc::rfc826).
// In the opposite direction, the network interface accepts Ethernet
// frames, checks if they are intended for it, and if so, processes
// the the payload depending on its type. If it's an IPv4 datagram,
// the network interface passes it up the stack. If it's an ARP
// request or reply, the network interface processes the frame
// and learns or replies as necessary.
class NetworkInterface
{
private:
  // The maximum time for the ARP cache table
  size_t MAX_CACHE_TIME = 30000;

  // The maximum time that the pending ARP reply wait for any next hop IP that was sent
  size_t MAX_WAITING_TIME = 5000;

  // Ethernet (known as hardware, network-access, or link-layer) address of the interface
  EthernetAddress ethernet_address_;

  // IP (known as Internet-layer or network-layer) address of the interface
  Address ip_address_;

  struct Ether_Addr_Entry {
      EthernetAddress MAC_addr;
      size_t caching_time;
  };
  
  // The ARP Table that stores IP address and corresponding MAC address (<IP, Ether_Addr_Entry>)
  std::map<uint32_t, Ether_Addr_Entry> ARP_table = std::map<uint32_t, Ether_Addr_Entry>();

  // ready-to-be-sent queue
  std::queue<EthernetFrame> ready2_sent_q = std::queue<EthernetFrame>();

  struct Waiting_Packet {
      uint32_t dst_ip;  // next_hop_ip that currently dont have MAC addr
      EthernetFrame waiting_frame;  // the EthernetFrame
      size_t time;  // the time that this waiting packet is created
  };

  // waiting queue
  std::queue<Waiting_Packet> waiting_q = std::queue<Waiting_Packet>();

  // ARP Request Map that used to check if and when an APR request is sent
  std::map<uint32_t, size_t> request_history = std::map<uint32_t, size_t>();

  // return a ARP message according to 5 parameters
  ARPMessage make_arp_message(const EthernetAddress sender_ethernet_address, const uint32_t& sender_ip_address, 
                              const EthernetAddress target_ethernet_address, const uint32_t& target_ip_address, 
                              const uint16_t opcode);

  // return an ethernet frame according to 4 parameters
  EthernetFrame make_ethernet_frame(const EthernetAddress& dst, const EthernetAddress& src, 
                                    const uint16_t type, vector<Buffer> payload);



public:
  // Construct a network interface with given Ethernet (network-access-layer) and IP (internet-layer)
  // addresses
  NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address );

  // Access queue of Ethernet frames awaiting transmission
  std::optional<EthernetFrame> maybe_send();

  // Sends an IPv4 datagram, encapsulated in an Ethernet frame (if it knows the Ethernet destination
  // address). Will need to use [ARP](\ref rfc::rfc826) to look up the Ethernet destination address
  // for the next hop.
  // ("Sending" is accomplished by making sure maybe_send() will release the frame when next called,
  // but please consider the frame sent as soon as it is generated.)
  void send_datagram( const InternetDatagram& dgram, const Address& next_hop );

  // Receives an Ethernet frame and responds appropriately.
  // If type is IPv4, returns the datagram.
  // If type is ARP request, learn a mapping from the "sender" fields, and send an ARP reply.
  // If type is ARP reply, learn a mapping from the "sender" fields.
  std::optional<InternetDatagram> recv_frame( const EthernetFrame& frame );

  // Called periodically when time elapses
  void tick( size_t ms_since_last_tick );
};
