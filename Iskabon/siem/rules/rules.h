#ifndef RULES_H
#define RULES_H

#include <string>
#include <ctime>

// Function declarations
int detect_port_scan(std::string src_ip, int dst_port, time_t timestamp);
int detect_web_attack(std::string src_ip, std::string uri, std::string method);
int detect_ssh_bruteforce(std::string src_ip, std::string timestamp);

#endif
