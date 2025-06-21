#include <iostream>
#include "network_interface.h"
#include "tcp_handler.h"
#include "tuntap++.hh"
#include "tins/stp.h"   
#include "tins/tins.h"
#include <chrono>
#include <thread>
#include <net/if.h>


SimpleTCP::NetworkInterface net_if("simpletcp");
SimpleTCP::TCPHandler* server_handler_ptr = nullptr;
SimpleTCP::TCPHandler* client_handler_ptr = nullptr;

// Global callback for NetworkInterface
void packet_demux(const std::vector<uint8_t>& raw_packet) {
    Tins::IP ip_packet(&raw_packet[0], raw_packet.size());
    if (!ip_packet.pdu()) return; // Not an IP packet or malformed

    auto tcp = ip_packet.rfind_pdu<Tins::TCP>();
    if (tcp) {
        // Simple demultiplexing based on destination port for this toy example
        // In a real stack, you'd use the full 4-tuple (src_ip, src_port, dst_ip, dst_port)
        // to find the correct connection handler.
        if (server_handler_ptr && tcp->dport() == 12345) { // Assuming server listens on 12345
            std::cout << "[NET_IF_CALLBACK] Routing to Server Handler (port " << tcp->dport() << ")" << std::endl;
            server_handler_ptr->process_ip_packet(raw_packet);
        } else if (client_handler_ptr && tcp->dport() == 54321) { // Assuming client uses 54321 as its source port
             std::cout << "[NET_IF_CALLBACK] Routing to Client Handler (port " << tcp->dport() << ")" << std::endl;
            client_handler_ptr->process_ip_packet(raw_packet);
        } else {
            // std::cout << "[NET_IF_CALLBACK] Packet to unknown port: " << tcp->dport() << std::endl;
        }
    }
}


void run_server() {
    // Server Handler will use the NetworkInterface's IP
    SimpleTCP::SimpleTCPHandler server(net_if, net_if.get_ip_address(), 12345);
    server_handler_ptr = &server; // Make it accessible to the demux callback
    std::cout << "[SERVER] Initializing. Listening on " << net_if.get_ip_address().to_string() << ":12345" << std::endl;

    server.listen_and_accept(); // Blocks until connection

    if (server.get_current_state() == SimpleTCP::TCPState::ESTABLISHED) {
        std::cout << "[SERVER] Connection established!" << std::endl;
        std::string received = server.receive_data();
        if (!received.empty()) {
            std::cout << "[SERVER] Received: '" << received << "'" << std::endl;
            server.send_data("Hello back from server!");
        }
        server.close_connection();
         std::cout << "[SERVER] Connection closed." << std::endl;
    } else {
        std::cout << "[SERVER] Failed to establish connection. State: " << SimpleTCP::to_string(server.get_current_state()) << std::endl;
    }
    server_handler_ptr = nullptr;
}

void run_client() {
    // Client Handler will also use the NetworkInterface's IP as its source.
    // It needs a unique source port.
    SimpleTCP::SimpleTCPHandler client(net_if, net_if.get_ip_address(), 54321);
    client_handler_ptr = &client; // Make it accessible to the demux callback
    Tins::IPv4Address server_ip = net_if.get_ip_address(); // Server is on the same TUN IF
    uint16_t server_port = 12345;

    std::cout << "[CLIENT] Attempting to connect to " << server_ip.to_string() << ":" << server_port << std::endl;

    if (client.connect_to(server_ip, server_port)) {
        std::cout << "[CLIENT] Connected!" << std::endl;
        client.send_data("Hello from client!");
        std::string received = client.receive_data();
        if (!received.empty()) {
            std::cout << "[CLIENT] Received: '" << received << "'" << std::endl;
        }
        client.close_connection();
        std::cout << "[CLIENT] Connection closed." << std::endl;
    } else {
        std::cout << "[CLIENT] Connection failed. State: " << SimpleTCP::to_string(client.get_current_state()) << std::endl;
    }
    client_handler_ptr = nullptr;
}


int
main(){
    if (!net_if.init("10.0.5.1", "255.255.255.0")) {
        std::cerr << "Failed to initialize network interface." << std::endl;
        return 1;
    }

    std::cout << "Network Interface " << net_if.get_ip_address().to_string() << " initialized." << std::endl;
    net_if.start_listening(packet_demux);

    std::cout << "Listening for packets..." << std::endl;

    std::thread server_thread(run_server);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Give server time to start
    std::thread client_thread(run_client);
    server_thread.join();
    client_thread.join();
    net_if.stop_listening();
    std::cout << "Network interface stopped listening." << std::endl;
    std::cout << "Exiting application." << std::endl;
    // Cleanup
    if (server_handler_ptr) {
        delete server_handler_ptr;
    }
    if (client_handler_ptr) {
        delete client_handler_ptr;
    }
    net_if.~NetworkInterface(); // Explicitly call destructor for cleanup
    std::cout << "Network interface cleaned up." << std::endl;
    std::cout << "Application finished." << std::endl;

    return 0;
}
