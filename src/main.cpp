#include <iostream>
#include <bits/stdc++.h>
#include "tuntap++.hh"
#include "tins/stp.h"

int
main(){
    try {
        // Create a TUN interface (layer 3)
        tuntap::tuntap tun(TUNTAP_MODE_TUNNEL, 0);
        const std::string tun_name = "tun0";
        tun.name(tun_name);
        tun.mtu(1400);
        tun.ip("192.168.0.10", 24);
        tun.up();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
