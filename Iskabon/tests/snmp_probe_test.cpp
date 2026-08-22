#include "probes/snmp_probe.hpp"
#include <iostream>
#include <string>

using iskabon::probes::SnmpProbe;

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

// sysObjectID values mapped to a known enterprise prefix -> vendor, high.
static void test_known_enterprise_prefixes() {
    auto cisco = SnmpProbe::classify_oid("1.3.6.1.4.1.9.1.222");
    EXPECT_EQ(cisco.vendor, std::string("Cisco"));
    EXPECT_EQ(cisco.confidence, std::string("high"));

    auto juniper = SnmpProbe::classify_oid("1.3.6.1.4.1.2636.1.1.1.2.26");
    EXPECT_EQ(juniper.vendor, std::string("Juniper"));
    EXPECT_EQ(juniper.confidence, std::string("high"));

    auto fortinet = SnmpProbe::classify_oid("1.3.6.1.4.1.12356.101.1.2");
    EXPECT_EQ(fortinet.vendor, std::string("Fortinet"));
    EXPECT_EQ(fortinet.confidence, std::string("high"));

    auto f5 = SnmpProbe::classify_oid("1.3.6.1.4.1.3375.2.1.3.4");
    EXPECT_EQ(f5.vendor, std::string("F5"));
    EXPECT_EQ(f5.confidence, std::string("high"));

    auto hp = SnmpProbe::classify_oid("1.3.6.1.4.1.11.2.3.9.1");
    EXPECT_EQ(hp.vendor, std::string("HP"));
    EXPECT_EQ(hp.confidence, std::string("high"));
}

// OID retrieved but not in the table -> low confidence.
static void test_unmapped_oid_is_low_confidence() {
    auto m = SnmpProbe::classify_oid("1.3.6.1.4.1.8072.3.2.10");
    EXPECT_EQ(m.vendor, std::string(""));
    EXPECT_EQ(m.confidence, std::string("low"));
}

// Prefix boundary: 1.3.6.1.4.1.9x must NOT match Cisco's 1.3.6.1.4.1.9.
static void test_prefix_boundary_no_false_positive() {
    auto m = SnmpProbe::classify_oid("1.3.6.1.4.1.91.2.1");
    EXPECT_EQ(m.vendor, std::string(""));
    EXPECT_EQ(m.confidence, std::string("low"));

    auto n = SnmpProbe::classify_oid("1.3.6.1.4.1.110.1.2");
    EXPECT_EQ(n.vendor, std::string(""));
    EXPECT_EQ(n.confidence, std::string("low"));
}

// Empty / missing raw value (query failed or timed out) -> none.
static void test_failed_query_is_none() {
    auto empty = SnmpProbe::classify_oid("");
    EXPECT_EQ(empty.vendor, std::string(""));
    EXPECT_EQ(empty.confidence, std::string("none"));

    auto blank = SnmpProbe::classify_oid("   \r\n\t ");
    EXPECT_EQ(blank.confidence, std::string("none"));
}

int main() {
    test_known_enterprise_prefixes();
    test_unmapped_oid_is_low_confidence();
    test_prefix_boundary_no_false_positive();
    test_failed_query_is_none();
    if (failures == 0)
        std::cout << "[+] snmp_probe_test: all tests passed\n";
    else
        std::cout << "[-] snmp_probe_test: " << failures
                  << " failure(s)\n";
    return failures ? 1 : 0;
}
