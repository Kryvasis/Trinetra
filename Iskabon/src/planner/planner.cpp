#include "planner/planner.hpp"

namespace iskabon::planner {

const std::vector<int>& default_tcp_ports() {
    static const std::vector<int> ports = {
        20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,
        143,161,389,443,445,465,514,587,631,993,995,1080,1194,1433,
        1521,1723,1883,2049,2375,2376,3306,3389,5060,5432,5672,5900,
        6379,6443,8000,8080,8443,9000,9042,9200,9418,11211,27017
    };
    return ports;
}

const std::vector<int>& default_udp_ports() {
    static const std::vector<int> ports = {
        53,67,68,69,111,123,137,138,161,389,500,514,520,
        631,1434,1900,4500,5353,11211
    };
    return ports;
}

std::vector<ProbeJob> build(
    const std::vector<std::string>& hosts,
    const std::vector<Protocol>&    protocols)
{
    std::vector<ProbeJob> jobs;
    jobs.reserve(hosts.size() * 80);

    for (const auto& host : hosts) {
        for (Protocol p : protocols) {
            if (p == Protocol::ICMP) {
                jobs.push_back({ host, Protocol::ICMP, 0 });
            } else if (p == Protocol::TCP) {
                for (int port : default_tcp_ports())
                    jobs.push_back({ host, Protocol::TCP, port });
            } else if (p == Protocol::UDP) {
                for (int port : default_udp_ports())
                    jobs.push_back({ host, Protocol::UDP, port });
            }
        }
    }
    return jobs;
}

} // namespace iskabon::planner
