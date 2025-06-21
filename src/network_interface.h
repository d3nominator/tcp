#ifndef NETWORK_INTERFACE_H
#define NETWORK_INTERFACE_H

#include <string>
#include <vector>
#include <memory>
#include <functional> // for std::function
#include <tins/tins.h>
#include <tuntap/tun.hh>

namespace SimpleTCP{

class
NetworkInterface{

public:
   NetworkInterface(const std::string& dev_name = "simpletun");
   ~NetworkInterface();

   bool init(const std::string& ip_address,const std::string& netmask);
   void start_listening(std::function<void(const std::vector<uint8_t>&));
   void stop_listening();

   bool send_packet(const Tins::PDU& pdu);

   Tins::IPv4Address get_ip_address() const;

private:
   void listening_loop();
   std::string dev_name_base_;
   std::string actual_dev_name_;
   std::unique_ptr<TunTap::Tun> tun_device_;
   Tins::IPv4Address ip_address_;

   std::thread listener_thread_;
   std::atomic<bool> running_{false};
   std::function<void(const std::vector<uint8_t>&) packet_callback_;
};

}

#endif

