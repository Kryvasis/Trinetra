// siem/rules/web_attack.cpp
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <regex>
#include <iomanip>
#include <chrono>

using namespace std;

// Configuration
const int WEB_ATTACK_THRESHOLD = 3;  // 3+ attempts from same IP

// Store attack attempts
map<string, int> attack_counts;      // src_ip -> count
map<string, vector<string>> attack_logs; // src_ip -> attack types

string get_current_time() {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << put_time(localtime(&now_time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int detect_web_attack(string src_ip, string uri, string method) {
    // Check for attack patterns
    vector<string> attack_patterns = {
        "' OR '1'='1",  // SQL Injection
        "<script>",      // XSS
        "../",           // Path Traversal
        ";",             // Command Injection
        "UNION SELECT"   // SQL Injection
    };
    
    bool attack_detected = false;
    string attack_type = "Unknown";
    
    for (string pattern : attack_patterns) {
        if (uri.find(pattern) != string::npos) {
            attack_detected = true;
            attack_type = pattern;
            break;
        }
    }
    
    if (attack_detected) {
        attack_counts[src_ip]++;
        attack_logs[src_ip].push_back(attack_type);
        
        if (attack_counts[src_ip] >= WEB_ATTACK_THRESHOLD) {
            cout << "   ALERT [HIGH] Web attack detected from " << src_ip << endl;
            cout << "   Attack type: " << attack_type << endl;
            cout << "   URI: " << uri << endl;
            cout << "   Method: " << method << endl;
            cout << "   Attempts: " << attack_counts[src_ip] << endl;
            cout << "   Time: " << get_current_time() << endl;
            cout << "   ---" << endl;
            return 1;
        }
    }
    
    return 0;
}

int main() {
    cout << "=== Iskabon SIEM — Web Attack Detection ===" << endl;
    cout << "Threshold: " << WEB_ATTACK_THRESHOLD << " attempts from same IP" << endl;
    cout << "============================================" << endl << endl;
    
    string attacker = "192.168.1.200";
    
    // Simulate web attacks
    vector<string> attacks = {
        "/login?username=admin' OR '1'='1",
        "/search?q=<script>alert(1)</script>",
        "/download?file=../../../etc/passwd",
        "/admin?cmd=whoami;"
    };
    
    for (string attack : attacks) {
        cout << "[LOG] " << attacker << " -> " << attack << endl;
        detect_web_attack(attacker, attack, "GET");
    }
    
    return 0;
}
