#include "cli/args.hpp"
#include "utils/constants.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace iskabon::cli {

void print_usage(const char* prog) {
    std::cout << "\nUsage:\n"
              << "  " << prog << " <session_name> <target_router> <target> [options]\n\n"
              << "Options:\n"
              << "  --protocols  <all|icmp,tcp,udp>   default: all\n"
              << "  --workers    <N>                  default: 256\n"
              << "  --timeout    <seconds>            default: 0.8\n\n"
              << "Example:\n"
              << "  " << prog << " lab-session 192.168.1.1 192.168.1.0/24 --protocols tcp,udp\n\n";
}

Args parse(int argc, char** argv) {
    if (argc < 4) {
        print_usage(argv[0]);
        throw std::invalid_argument("Not enough arguments.");
    }

    Args a;
    a.session_name  = argv[1];
    a.target_router = argv[2];
    a.target        = argv[3];
    a.protocols     = { Protocol::TCP, Protocol::UDP, Protocol::ICMP };
    a.workers       = static_cast<int>(
        std::max(64u, std::thread::hardware_concurrency() * 32));
    a.timeout       = 0.8;

    for (int i = 4; i < argc; ++i) {
        std::string flag = argv[i];
        if (flag == "--protocols" && i+1 < argc) {
            a.protocols.clear();
            std::string raw = argv[++i];
            if (raw == "all") {
                a.protocols = { Protocol::TCP, Protocol::UDP, Protocol::ICMP };
            } else {
                std::istringstream ss(raw);
                std::string token;
                while (std::getline(ss, token, ','))
                    a.protocols.push_back(protocol_from_str(token));
            }
        } else if (flag == "--workers" && i+1 < argc) {
            a.workers = std::stoi(argv[++i]);
        } else if (flag == "--timeout" && i+1 < argc) {
            a.timeout = std::stod(argv[++i]);
        } else {
            throw std::invalid_argument("Unknown argument: " + flag);
        }
    }
    return a;
}

} // namespace iskabon::cli
