#ifndef TCP_HANDLER_H
#define TCP_HANDLER

#include "tcp_common.h"
#include "network_interface.h"
#include "tins/tins.h"
#include <mutex>
#include <condition_variable>
#include <queue>

namespace SimpleTCP{

class TCPHandler{
    public:
        TCPHandler(NetworkInterface& net_if, Tins::IPv4Address local_ip, uint16_t local_port);

        // server side
        void listen_and_accept();

        //client side
        bool connect_to(Tins::IPv4Address remote_ip, uint16_t remote_port );

        // Data Transfer
        std::string receive_data(size_t max_len = 1024, int timeout_ms = 500);

        //closing
        void close_connection();

        void process_ip_packet(const std::vector<uint8_t> & raw_packet);


        TCPState get_current_state() const;

    private:
        void set_state(TCPState new_state);
        void send_tcp_segment(Tins::TCP::Flags flags,const Tins::RAWPDU* payload = nullptr);

        //specific state handling logic
        void handle_syn(const Tins::TCP& tcp_segment, const Tins::IP& ip_packet);
        void handle_syn_ack(const Tins::TCP& tcp_segment);
        void handle_ack(const Tins::TCP& tcp_segment);
        void handle_fin(const Tins::TCP& tcp_segment);
        void handle_data(const Tins::TCP& tcp_segment);

        NetworkInterface& net_interface_;

        Tins::IPv4Address local_ip_;
        uint16_t local_port_;
        Tins::IPv4Address remote_ip_;
        uint16_t remote_port_;


        TCPState current_state_ = TCPState::CLOSED;

        //sequence numbers
        uint32_t isn_ = 0;
        uint32_t snd_nxt_ = 0;
        uint32_t rcv_nxt_ = 0;


        //simple recived buffer
        std::queue<uint8_t> app_recieve_buffer_;
        std::mutex app_receive_buffer_mutex_;
        std::condition_variable app_receive_cv_;


        bool active_closed = false;
};

}

#endif
