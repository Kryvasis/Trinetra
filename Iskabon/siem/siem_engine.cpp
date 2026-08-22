// siem/siem_engine.cpp
#include <iostream>
#include <string>
#include <ctime>
#include "rules/rules.h"

using namespace std;

int main() {
    cout << "========================================" << endl;
    cout << "     ISKABON SIEM ENGINE v0.1          " << endl;
    cout << "     Multi-Attack Detection             " << endl;
    cout << "========================================" << endl << endl;
    
    cout << "[*] Loading rules..." << endl;
    cout << "    - SSH Brute Force (5 attempts/60s)" << endl;
    cout << "    - Port Scan (10 unique ports/60s)" << endl;
    cout << "    - Web Attack (3 attack patterns)" << endl;
    cout << endl;

    cout << "[*] SIEM Engine ready." << endl;
    cout << "[*] Waiting for logs..." << endl << endl;
    
    // Simulate a real attack scenario
    cout << "=== SIMULATION: Multi-Stage Attack ===" << endl;
    
    // Stage 1: Port Scan
    cout << "\n[STAGE 1] Attacker performs port scan..." << endl;
    time_t now = time(nullptr);
    detect_port_scan("10.0.0.50", 22, now);
    detect_port_scan("10.0.0.50", 23, now);
    detect_port_scan("10.0.0.50", 80, now);
    detect_port_scan("10.0.0.50", 443, now);
    detect_port_scan("10.0.0.50", 3306, now);
    detect_port_scan("10.0.0.50", 5432, now);
    detect_port_scan("10.0.0.50", 6379, now);
    detect_port_scan("10.0.0.50", 8080, now);
    detect_port_scan("10.0.0.50", 9200, now);
    detect_port_scan("10.0.0.50", 27017, now);
    
    // Stage 2: Web Attack
    cout << "\n[STAGE 2] Attacker tries SQL injection..." << endl;
    detect_web_attack("10.0.0.50", "/login?username=admin' OR '1'='1", "GET");
    detect_web_attack("10.0.0.50", "/search?q=<script>alert(1)</script>", "GET");
    detect_web_attack("10.0.0.50", "/download?file=../../../etc/passwd", "GET");
    
    // Stage 3: SSH Brute Force
    cout << "\n[STAGE 3] Attacker attempts SSH brute force..." << endl;
    detect_ssh_bruteforce("10.0.0.50", "2026-07-31T00:20:00Z");
    detect_ssh_bruteforce("10.0.0.50", "2026-07-31T00:20:10Z");
    detect_ssh_bruteforce("10.0.0.50", "2026-07-31T00:20:20Z");
    detect_ssh_bruteforce("10.0.0.50", "2026-07-31T00:20:30Z");
    detect_ssh_bruteforce("10.0.0.50", "2026-07-31T00:20:40Z");
    
    cout << "\n========================================" << endl;
    cout << "[*] Simulation complete." << endl;
    cout << "========================================" << endl;
    
    return 0;
}
