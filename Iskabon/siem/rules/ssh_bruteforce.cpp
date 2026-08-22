// siem/rules/ssh_bruteforce.cpp
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

using namespace std;

// Configuration
const int SSH_THRESHOLD = 5;
const int SSH_TIME_WINDOW = 60;

map<string, vector<time_t>> failed_attempts;

string get_current_time_ssh() {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << put_time(localtime(&now_time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int detect_ssh_bruteforce(string src_ip, string timestamp) {
    time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    failed_attempts[src_ip].push_back(now);
    
    time_t cutoff = now - SSH_TIME_WINDOW;
    vector<time_t> recent;
    for (time_t t : failed_attempts[src_ip]) {
        if (t >= cutoff) {
            recent.push_back(t);
        }
    }
    failed_attempts[src_ip] = recent;
    
    if (recent.size() >= SSH_THRESHOLD) {
        cout << "   ALERT [HIGH] SSH brute force detected from " << src_ip << endl;
        cout << "   Attempts: " << recent.size() << " in last " << SSH_TIME_WINDOW << " seconds" << endl;
        cout << "   Time: " << get_current_time_ssh() << endl;
        cout << "   ---" << endl;
        return 1;
    }
    return 0;
}
