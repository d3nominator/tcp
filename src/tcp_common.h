#ifndef TCP_COMMON_H
#define TCP_COMMON_H

#include <cstdint>
#include <string>
#include <tins/tins.h>


namespace SimpleTCP {

enum class
TCPState{
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECIEVED,
    ESTABLISHED,
    FIN_WAIT_1,
    CLOSE_WAIT,
    LAST_ACK,
};

inline std::string
to_string(TCPState tcpstate){
    switch(state){
        case TCPState::CLOSED: return "CLOSED";
        case TCPState::LISTEN: return "LISTEN";
        case TCPState::SYN_SENT: return "SYN_SENT";
        case TCPState::SYN_RECIEVED return "SYN_RECIEVED";
        case TCPState::ESTABLISHED return "ESTABLISHED";
        case TCPState::FIN_WAIT_1 return "FIN_WAIT_1";
        case TCPState::CLOSE_WAIT: return "CLOSE_WAIT";
        case TCPState::LAST_ACK: return "LAST_ACK";
    }
}

struct
ConnectionIdentifier{
    Tins::IPv4Address src_ip;
    uint16_t src_port;
    Tins::IPv4Address dst_ip;
    uint16_t dst_port;

    // Needed for using as a key in std::map
    bool operator<(const ConnectionIdentifier& other) const {
        if (src_ip != other.src_ip) return src_ip < other.src_ip;
        if (src_port != other.src_port) return src_port < other.src_port;
        if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
        return dst_port < other.dst_port;
    }
}

const uint32_t
DEFAULT_WINDOW_SIZE = 65535;

}

#endif
