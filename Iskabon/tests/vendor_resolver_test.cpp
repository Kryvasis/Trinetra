#include "vendor_resolver/vendor_resolver.hpp"
#include <iostream>
#include <string>

using namespace iskabon::vendor_resolver;

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

#define EXPECT_TRUE(cond)                                                   \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << "  "     \
                      << #cond << "\n";                                     \
            ++failures;                                                     \
        }                                                                   \
    } while (0)

// (a) SNMP-confirmed: sysObjectID resolved with high confidence wins.
static void test_snmp_confirmed() {
    SnmpEvidence snmp;
    snmp.raw_value    = "1.3.6.1.4.1.9.1.222";
    snmp.vendor_guess = "Cisco";
    snmp.confidence   = "high";

    auto r = resolve_vendor({}, {}, snmp);
    EXPECT_EQ(r.final_vendor, std::string("Cisco"));
    EXPECT_EQ(r.detection_method, std::string("snmp"));
    EXPECT_TRUE(r.confidence_score >= 0.9 && r.confidence_score <= 1.0);

    // Banner agreeing with SNMP nudges the score to the upper band.
    BannerEvidence banner;
    banner.vendor_guess = "Cisco";
    auto corroborated = resolve_vendor({}, banner, snmp);
    EXPECT_EQ(corroborated.final_vendor, std::string("Cisco"));
    EXPECT_TRUE(corroborated.confidence_score >= 0.95);
}

// (b) Banner-only: no SNMP signal, banner vendor_guess is used.
static void test_banner_only() {
    SnmpEvidence snmp;
    snmp.confidence = "none";

    BannerEvidence banner;
    banner.vendor_guess  = "nginx";
    banner.version_guess = "1.18.0";

    auto r = resolve_vendor({}, banner, snmp);
    EXPECT_EQ(r.final_vendor, std::string("nginx"));
    EXPECT_EQ(r.detection_method, std::string("banner"));
    EXPECT_TRUE(r.confidence_score >= 0.6 && r.confidence_score <= 0.8);

    // A strong matching stack fingerprint pushes the score to the top
    // of the banner band.
    StackFingerprint stack;
    stack.os_family     = "junos";
    stack.strong_match  = true;
    banner.vendor_guess = "Juniper";
    auto corroborated = resolve_vendor(stack, banner, snmp);
    EXPECT_EQ(corroborated.detection_method, std::string("banner"));
    EXPECT_TRUE(corroborated.confidence_score >= 0.8);
}

// (c) Conflicting sources -> unknown with low confidence.
static void test_conflict_is_unknown() {
    SnmpEvidence snmp;
    snmp.raw_value    = "1.3.6.1.4.1.2636.1.1.1";
    snmp.vendor_guess = "Juniper";
    snmp.confidence   = "high";

    BannerEvidence banner;
    banner.vendor_guess = "Cisco";

    StackFingerprint stack;
    stack.os_family    = "ios";
    stack.strong_match = true;

    auto r = resolve_vendor(stack, banner, snmp);
    EXPECT_EQ(r.final_vendor, std::string("unknown"));
    EXPECT_EQ(r.detection_method, std::string("conflict"));
    EXPECT_TRUE(r.confidence_score < 0.3);
}

// (c) cont: nothing resolves at all -> unknown below 0.3.
static void test_nothing_resolves() {
    auto r = resolve_vendor({}, {}, {});
    EXPECT_EQ(r.final_vendor, std::string("unknown"));
    EXPECT_EQ(r.detection_method, std::string("none"));
    EXPECT_TRUE(r.confidence_score < 0.3);
}

// Tier 3 fallback: only a strong stack match present.
static void test_stack_fallback() {
    StackFingerprint stack;
    stack.os_family    = "fortios";
    stack.strong_match = true;

    auto r = resolve_vendor(stack, {}, {});
    EXPECT_EQ(r.final_vendor, std::string("Fortinet"));
    EXPECT_EQ(r.detection_method, std::string("stack_fingerprint"));
    EXPECT_TRUE(r.confidence_score >= 0.3 && r.confidence_score <= 0.5);

    // Weak stack matches never reach tier 3.
    StackFingerprint weak;
    weak.os_family    = "linux";
    weak.strong_match = false;
    auto w = resolve_vendor(weak, {}, {});
    EXPECT_EQ(w.final_vendor, std::string("unknown"));
}

// Banner vs strong-stack disagreement (without SNMP) also conflicts.
static void test_banner_stack_conflict() {
    BannerEvidence banner;
    banner.vendor_guess = "ProFTPD";

    StackFingerprint stack;
    stack.os_family    = "nx-os";
    stack.strong_match = true;

    SnmpEvidence snmp;
    snmp.confidence = "low";

    auto r = resolve_vendor(stack, banner, snmp);
    EXPECT_EQ(r.final_vendor, std::string("unknown"));
    EXPECT_EQ(r.detection_method, std::string("conflict"));
}

int main() {
    test_snmp_confirmed();
    test_banner_only();
    test_conflict_is_unknown();
    test_nothing_resolves();
    test_stack_fallback();
    test_banner_stack_conflict();
    if (failures == 0)
        std::cout << "[+] vendor_resolver_test: all tests passed\n";
    else
        std::cout << "[-] vendor_resolver_test: " << failures
                  << " failure(s)\n";
    return failures ? 1 : 0;
}
