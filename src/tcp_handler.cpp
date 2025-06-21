#include "tcp_handler.h"
#include <iostream>
#include <random> // For generating Initial Sequence Number (ISN)
#include <chrono>

namespace SimpleTCP {

// Constructor: Initializes the handler with its network interface, IP, and port.
SimpleTCPHandler::SimpleTCPHandler(NetworkInterface& net_if, Tins::IPv4Address local_ip, uint16_t local_port)
    : net_interface_(net_if), local_ip_(local_ip), local_port_(local_port) {
    // Set initial state
    set_state(TCPState::CLOSED);

    // Generate a random Initial Sequence Number (ISN) for security
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    isn_ = distrib(gen);
    snd_nxt_ = isn_; // The first sequence number we will send is the ISN
}

// --- Public Methods ---

// "Server" side: Listens for an incoming connection and completes the 3-way handshake.
void SimpleTCPHandler::listen_and_accept() {
    set_state(TCPState::LISTEN);
    std::cout << "[TCP_HANDLER] State -> LISTEN. Waiting for incoming SYN..." << std::endl;

    // Block until the state changes from LISTEN, which happens when a valid SYN is received.
    // In a real application, a condition variable would be used here. We simulate this
    // by waiting for the state to change.
    std::unique_lock<std::mutex> lock(state_mutex_);
    state_change_cv_.wait(lock, [this] {
        return current_state_ != TCPState::LISTEN;
    });

    // After wait, the state should be SYN_RECEIVED. Now wait for the final ACK to establish.
    if (current_state_ == TCPState::SYN_RECEIVED) {
        std::cout << "[TCP_HANDLER] State -> SYN_RECEIVED. Waiting for final ACK..." << std::endl;
        state_change_cv_.wait(lock, [this] {
            return current_state_ == TCPState::ESTABLISHED || current_state_ == TCPState::CLOSED;
        });
    }
}

// "Client" side: Initiates a connection to a remote server.
bool SimpleTCPHandler::connect_to(Tins::IPv4Address remote_ip, uint16_t remote_port) {
    remote_ip_ = remote_ip;
    remote_port_ = remote_port;
    snd_nxt_ = isn_; // Start with our ISN

    // Send the initial SYN packet
    std::cout << "[TCP_HANDLER] Sending SYN to " << remote_ip_ << ":" << remote_port_ << std::endl;
    send_tcp_segment(Tins::TCP::SYN);
    set_state(TCPState::SYN_SENT);

    // Wait for the connection to be established or to fail (timeout).
    std::unique_lock<std::mutex> lock(state_mutex_);
    if (state_change_cv_.wait_for(lock, std::chrono::seconds(5), [this] {
        return current_state_ == TCPState::ESTABLISHED;
    })) {
        // Condition variable was notified and condition is true
        return true;
    } else {
        // Timed out
        std::cerr << "[TCP_HANDLER] Connect timed out." << std::endl;
        set_state(TCPState::CLOSED);
        return false;
    }
}

// Sends data once the connection is ESTABLISHED.
bool SimpleTCPHandler::send_data(const std::string& data) {
    if (get_current_state() != TCPState::ESTABLISHED) {
        std::cerr << "[TCP_HANDLER] Cannot send data: connection not established." << std::endl;
        return false;
    }

    // PSH (push) flag tells the receiver to pass the data to the application immediately.
    // ACK is always set for segments after the initial SYN.
    Tins::RawPDU payload(data);
    send_tcp_segment(Tins::TCP::PSH | Tins::TCP::ACK, &payload);

    // Increment our next sequence number by the size of the data sent.
    // NOTE: This is a simplified model. Real TCP waits for an ACK before considering
    // the data "sent" for good.
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        snd_nxt_ += data.length();
    }
    return true;
}

// Receives data. Blocks until data is available or a timeout occurs.
std::string SimpleTCPHandler::receive_data(size_t max_len, int timeout_ms) {
    std::unique_lock<std::mutex> lock(app_receive_buffer_mutex_);

    // Wait for data to arrive in the buffer
    if (!app_receive_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
        return !app_receive_buffer_.empty();
    })) {
        // Timed out
        return "";
    }

    std::string data;
    data.reserve(std::min(max_len, app_receive_buffer_.size()));
    while (!app_receive_buffer_.empty() && data.length() < max_len) {
        data += app_receive_buffer_.front();
        app_receive_buffer_.pop();
    }
    return data;
}

// Initiates an active close of the connection.
void SimpleTCPHandler::close_connection() {
    TCPState state = get_current_state();
    if (state != TCPState::ESTABLISHED && state != TCPState::CLOSE_WAIT) {
        set_state(TCPState::CLOSED);
        return;
    }

    active_close_ = true; // We are initiating the close
    if (state == TCPState::ESTABLISHED) {
        std::cout << "[TCP_HANDLER] Initiating active close (sending FIN)." << std::endl;
        send_tcp_segment(Tins::TCP::FIN | Tins::TCP::ACK);
        set_state(TCPState::FIN_WAIT_1);
    } else if (state == TCPState::CLOSE_WAIT) {
        // This happens after a passive close, we are now sending our FIN
        std::cout << "[TCP_HANDLER] Closing from CLOSE_WAIT (sending FIN)." << std::endl;
        send_tcp_segment(Tins::TCP::FIN | Tins::TCP::ACK);
        set_state(TCPState::LAST_ACK);
    }
}

// This is the main entry point for processing incoming packets from the NetworkInterface.
void SimpleTCPHandler::process_ip_packet(const std::vector<uint8_t>& raw_packet) {
    Tins::IP ip_packet(&raw_packet[0], raw_packet.size());
    auto tcp_segment = ip_packet.rfind_pdu<Tins::TCP>();

    if (!tcp_segment) {
        return; // Not a TCP packet
    }

    // Basic check to see if this packet is for our connection
    // For simplicity, we ignore IP addresses and just check ports
    if (get_current_state() != TCPState::LISTEN &&
       (tcp_segment->sport() != remote_port_ || tcp_segment->dport() != local_port_)) {
        // Packet is not part of our current active connection
        return;
    }

    std::cout << "[TCP_HANDLER] Processing packet in state " << to_string(get_current_state()) << ". Flags: ";
    if(tcp_segment->get_flag(Tins::TCP::SYN)) std::cout << "SYN ";
    if(tcp_segment->get_flag(Tins::TCP::ACK)) std::cout << "ACK ";
    if(tcp_segment->get_flag(Tins::TCP::FIN)) std::cout << "FIN ";
    if(tcp_segment->get_flag(Tins::TCP::PSH)) std::cout << "PSH ";
    std::cout << std::endl;


    // --- State-based Packet Handling ---
    TCPState current_state_snapshot = get_current_state();

    if (tcp_segment->get_flag(Tins::TCP::SYN)) {
        handle_syn(*tcp_segment, ip_packet);
    }
    // SYN-ACK is a SYN and an ACK
    else if (tcp_segment->get_flag(Tins::TCP::ACK)) {
        handle_ack(*tcp_segment);
    }

    if (tcp_segment->pdu()) { // Check if there is a payload
        handle_data(*tcp_segment);
    }
    
    if (tcp_segment->get_flag(Tins::TCP::FIN)) {
        handle_fin(*tcp_segment);
    }
}


TCPState SimpleTCPHandler::get_current_state() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return current_state_;
}


// --- Private Helper Methods ---

// Sets the current state and notifies any waiting threads.
void SimpleTCPHandler::set_state(TCPState new_state) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (current_state_ != new_state) {
        std::cout << "[TCP_HANDLER] State transition: " << to_string(current_state_) << " -> " << to_string(new_state) << std::endl;
        current_state_ = new_state;
        // Wake up any threads that are waiting on a state change (e.g., in connect() or listen()).
        state_change_cv_.notify_all();
    }
}

// Central function to build and send a TCP segment.
void SimpleTCPHandler::send_tcp_segment(Tins::TCP::Flags flags, const Tins::RawPDU* payload) {
    Tins::TCP segment;
    segment.sport(local_port_);
    segment.dport(remote_port_);

    { // Lock to protect sequence numbers
        std::lock_guard<std::mutex> lock(state_mutex_);
        segment.seq(snd_nxt_);
        // ACK flag should be set on all packets after the initial SYN
        if (flags & Tins::TCP::ACK) {
            segment.ack_seq(rcv_nxt_);
        }
    }
    
    segment.window(DEFAULT_WINDOW_SIZE);
    segment.set_flags(flags);

    Tins::IP packet = Tins::IP(remote_ip_, local_ip_) / segment;
    if (payload) {
        packet /= *payload;
    }

    // The NetworkInterface handles serialization and sending
    net_interface_.send_packet(packet);
}

// Handles incoming SYN packets (for server in LISTEN state)
void SimpleTCPHandler::handle_syn(const Tins::TCP& tcp_segment, const Tins::IP& ip_packet) {
    if (get_current_state() != TCPState::LISTEN) {
        return; // We only care about SYN when listening
    }
    std::lock_guard<std::mutex> lock(state_mutex_);
    remote_ip_ = ip_packet.src_addr();
    remote_port_ = tcp_segment.sport();
    rcv_nxt_ = tcp_segment.seq() + 1;
    snd_nxt_ = isn_; // Use our initial sequence number

    send_tcp_segment(Tins::TCP::SYN | Tins::TCP::ACK);
    snd_nxt_++; // SYN consumes one sequence number
    set_state(TCPState::SYN_RECEIVED);
}

// Handles incoming ACK packets (for handshake, data, and FINs)
void SimpleTCPHandler::handle_ack(const Tins::TCP& tcp_segment) {
    // If we are waiting for a SYN-ACK, this must be it
    if (get_current_state() == TCPState::SYN_SENT && tcp_segment.get_flag(Tins::TCP::SYN)) {
         handle_syn_ack(tcp_segment);
         return;
    }

    // Check if the ACK is for our FIN
    if (get_current_state() == TCPState::FIN_WAIT_1) {
        set_state(TCPState::FIN_WAIT_2);
        // Now we wait for a FIN from the other side
        return;
    }
    
    if (get_current_state() == TCPState::LAST_ACK) {
        set_state(TCPState::CLOSED); // Final ACK received, connection is done.
        return;
    }

    // If we are in SYN_RECEIVED, this is the final ACK of the 3-way handshake
    if (get_current_state() == TCPState::SYN_RECEIVED) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        // The ACK should be for our SYN
        if (tcp_segment.ack_seq() == snd_nxt_) {
            set_state(TCPState::ESTABLISHED);
        }
    }
}

// Specific handler for a SYN-ACK packet (client side)
void SimpleTCPHandler::handle_syn_ack(const Tins::TCP& tcp_segment) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    // Check if their ACK is for our SYN, and that it's a SYN-ACK
    if (tcp_segment.ack_seq() == snd_nxt_ + 1) {
        snd_nxt_++; // Acknowledge their SYN
        rcv_nxt_ = tcp_segment.seq() + 1;
        send_tcp_segment(Tins::TCP::ACK); // Send final ACK of handshake
        set_state(TCPState::ESTABLISHED);
    }
}

// Handles incoming FIN packets
void SimpleTCPHandler::handle_fin(const Tins::TCP& tcp_segment) {
    TCPState state = get_current_state();
    if (state == TCPState::ESTABLISHED) {
        // This is a passive close, initiated by the peer
        std::lock_guard<std::mutex> lock(state_mutex_);
        rcv_nxt_ = tcp_segment.seq() + 1;
        send_tcp_segment(Tins::TCP::ACK); // Acknowledge their FIN
        set_state(TCPState::CLOSE_WAIT);
        // The application now needs to call close_connection() to send our FIN
    } else if (state == TCPState::FIN_WAIT_2) {
        // This is the peer's FIN after we already sent ours
         std::lock_guard<std::mutex> lock(state_mutex_);
        rcv_nxt_ = tcp_segment.seq() + 1;
        send_tcp_segment(Tins::TCP::ACK);
        // For simplicity, transition directly to closed. Real TCP goes to TIME_WAIT.
        set_state(TCPState::CLOSED);
    }
}

// Handles incoming data
void SimpleTCPHandler::handle_data(const Tins::TCP& tcp_segment) {
    if (get_current_state() != TCPState::ESTABLISHED) return;

    auto& payload = tcp_segment.rfind_pdu<Tins::RawPDU>();
    const auto& payload_data = payload.payload();

    if (!payload_data.empty()) {
        std::cout << "[TCP_HANDLER] Received " << payload_data.size() << " bytes of data." << std::endl;
        
        { // Lock the application buffer to add the data
            std::lock_guard<std::mutex> lock(app_receive_buffer_mutex_);
            for (uint8_t byte : payload_data) {
                app_receive_buffer_.push(byte);
            }
        }
        app_receive_cv_.notify_one(); // Notify the receiving thread

        // Acknowledge the data we just received
        {
             std::lock_guard<std::mutex> lock(state_mutex_);
            rcv_nxt_ += payload_data.size();
        }
        send_tcp_segment(Tins::TCP::ACK);
    }
}

} // namespace SimpleTCP
