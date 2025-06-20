#include "network_interface.h"
#include <tuntap/commands.hh> // For Tuntap::Commands::set_ip, up, down
#include <iostream>
#include <stdexcept>
#include <sys/select.h> // For select()

namespace SimpleTCP {

// Constructor: Initializes the base name for the TUN device.
NetworkInterface::NetworkInterface(const std::string& dev_name)
    : dev_name_base_(dev_name) {}

// Destructor: Ensures the listening thread is stopped and the device is closed.
NetworkInterface::~NetworkInterface() {
    // If the listener thread is running, stop it gracefully.
    if (running_.load()) {
        stop_listening();
    }
}

// Initializes the TUN device: creates it, sets IP/netmask, and brings it up.
bool NetworkInterface::init(const std::string& ip_address, const std::string& netmask) {
    try {
        // 1. Create the TUN device.
        tun_device_ = std::make_unique<Tuntap::Tun>(dev_name_base_);
        actual_dev_name_ = tun_device_->name();
        std::cout << "[NET_IF] Created TUN device: " << actual_dev_name_ << std::endl;

        // 2. Set the IP address and netmask for the device.
        std::cout << "[NET_IF] Setting IP: " << ip_address << "/" << netmask << std::endl;
        Tuntap::Commands::set_ip(actual_dev_name_, ip_address, netmask);
        
        // Store the IP address for later use.
        ip_address_ = Tins::IPv4Address(ip_address);

        // 3. Bring the interface up.
        std::cout << "[NET_IF] Bringing device up." << std::endl;
        Tuntap::Commands::up(actual_dev_name_);

    } catch (const std::runtime_error& e) {
        std::cerr << "[NET_IF] Error initializing TUN device: " << e.what() << std::endl;
        std::cerr << "[NET_IF] Make sure you are running with sufficient privileges (e.g., sudo)." << std::endl;
        return false;
    } catch (const Tuntap::InterfaceError& e) {
        std::cerr << "[NET_IF] Error configuring TUN interface: " << e.what() << std::endl;
        return false;
    }
    return true;
}

// Starts a new thread that continuously listens for incoming packets.
void NetworkInterface::start_listening(std::function<void(const std::vector<uint8_t>&)> on_packet_received) {
    if (running_.load()) {
        std::cout << "[NET_IF] Listener is already running." << std::endl;
        return;
    }

    packet_callback_ = on_packet_received;
    running_.store(true);

    // Start the listening loop in a new thread.
    listener_thread_ = std::thread(&NetworkInterface::listening_loop, this);
    std::cout << "[NET_IF] Packet listener thread started." << std::endl;
}

// Stops the listening thread and waits for it to terminate.
void NetworkInterface::stop_listening() {
    running_.store(false);
    if (listener_thread_.joinable()) {
        listener_thread_.join();
        std::cout << "[NET_IF] Packet listener thread stopped." << std::endl;
    }
}

// Sends a Tins PDU (like an IP packet) over the TUN device.
bool NetworkInterface::send_packet(const Tins::PDU& pdu) {
    if (!tun_device_ || !tun_device_->is_open()) {
        std::cerr << "[NET_IF] Cannot send packet, TUN device is not open." << std::endl;
        return false;
    }

    try {
        // Serialize the PDU into a byte vector. libtins handles all the header
        // construction, checksums, etc.
        Tins::PDU::serialization_type buffer = pdu.serialize();
        
        // Write the byte vector to the TUN device.
        tun_device_->write(buffer);

    } catch (const std::exception& e) {
        std::cerr << "[NET_IF] Error sending packet: " << e.what() << std::endl;
        return false;
    }
    return true;
}

// Returns the IP address configured for this interface.
Tins::IPv4Address NetworkInterface::get_ip_address() const {
    return ip_address_;
}

// The core loop executed by the listener thread.
void NetworkInterface::listening_loop() {
    if (!tun_device_ || !tun_device_->is_open()) {
        std::cerr << "[NET_IF] Listening loop cannot start: TUN device not open." << std::endl;
        return;
    }

    int fd = tun_device_->fd();
    
    // This loop continues as long as running_ is true.
    while (running_.load()) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);

        // Set up a timeout for select(). This is crucial. Without a timeout,
        // select() would block indefinitely, and we could never stop the thread
        // cleanly by setting running_ to false. A 1-second timeout is a
        // reasonable compromise.
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // select() waits for I/O to become available on the specified file descriptor.
        int activity = select(fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (activity < 0) {
            // Error in select()
            std::cerr << "[NET_IF] Error in select(): " << strerror(errno) << std::endl;
            continue;
        }

        if (activity == 0) {
            // Timeout occurred, no data to read. This is normal.
            // The loop will now re-check the `running_` flag.
            continue;
        }

        if (FD_ISSET(fd, &read_fds)) {
            // Data is available to read from the TUN device.
            try {
                // Read the raw IP packet.
                std::vector<uint8_t> buffer = tun_device_->read(1500); // Read up to MTU size
                if (!buffer.empty() && packet_callback_) {
                    // Pass the raw packet data to the callback function for processing.
                    packet_callback_(buffer);
                }
            } catch (const std::exception& e) {
                std::cerr << "[NET_IF] Error reading from TUN device: " << e.what() << std::endl;
            }
        }
    }
}

} // namespace SimpleTCP
