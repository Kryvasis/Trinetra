#include "probes/banner_probe.hpp"
#include <iostream>
#include <string>

using iskabon::probes::BannerProbe;

static int failures = 0;

#define EXPECT_EQ(a, b)                                                     \
    do {                                                                    \
        if ((a) != (b)) {                                                   \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << "  "     \
                      << #a << " != " << #b << "  ("                        \
                      << (a) << " vs " << (b) << ")\n";                     \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

static void test_ssh_banner() {
    auto g = BannerProbe::parse_vendor_version("SSH-2.0-OpenSSH_8.2p1");
    EXPECT_EQ(g.vendor, std::string("OpenSSH"));
    EXPECT_EQ(g.version, std::string("8.2p1"));
}

static void test_http_server_header() {
    auto g = BannerProbe::parse_vendor_version(
        "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html");
    EXPECT_EQ(g.vendor, std::string("nginx"));
    EXPECT_EQ(g.version, std::string("1.18.0"));
}

static void test_ftp_banner() {
    auto g = BannerProbe::parse_vendor_version(
        "220 ProFTPD 1.3.5 Server (ProFTPD) [::ffff:10.0.0.1]");
    EXPECT_EQ(g.vendor, std::string("ProFTPD"));
    EXPECT_EQ(g.version, std::string("1.3.5"));
}

static void test_unknown_banner_kept_raw() {
    auto g = BannerProbe::parse_vendor_version("\xff\xfd\x18welcome to router");
    EXPECT_EQ(g.vendor, std::string());
    EXPECT_EQ(g.version, std::string());
}

int main() {
    test_ssh_banner();
    test_http_server_header();
    test_ftp_banner();
    test_unknown_banner_kept_raw();
    if (failures == 0)
        std::cout << "[+] banner_probe_test: all tests passed\n";
    else
        std::cout << "[-] banner_probe_test: " << failures
                  << " failure(s)\n";
    return failures ? 1 : 0;
}
