#include "utils/sha256.hpp"
#include <array>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace iskabon::utils {

namespace {

constexpr std::array<uint32_t, 64> K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch (uint32_t x,uint32_t y,uint32_t z) { return (x&y)^(~x&z); }
inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z) { return (x&y)^(x&z)^(y&z); }
inline uint32_t sig0(uint32_t x){ return rotr(x,2)^rotr(x,13)^rotr(x,22); }
inline uint32_t sig1(uint32_t x){ return rotr(x,6)^rotr(x,11)^rotr(x,25); }
inline uint32_t gam0(uint32_t x){ return rotr(x,7)^rotr(x,18)^(x>>3); }
inline uint32_t gam1(uint32_t x){ return rotr(x,17)^rotr(x,19)^(x>>10); }

} // anon

std::string sha256(std::string_view input) {
    std::array<uint32_t,8> h = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    // Pre-processing: pad message
    uint64_t bit_len = static_cast<uint64_t>(input.size()) * 8;
    std::string msg(input);
    msg += static_cast<char>(0x80);
    while ((msg.size() % 64) != 56) msg += static_cast<char>(0x00);
    for (int i = 7; i >= 0; --i)
        msg += static_cast<char>((bit_len >> (i * 8)) & 0xFF);

    // Process each 512-bit chunk
    for (size_t i = 0; i < msg.size(); i += 64) {
        std::array<uint32_t,64> w{};
        for (int j = 0; j < 16; ++j) {
            w[j] = (static_cast<uint8_t>(msg[i+j*4])   << 24)
                 | (static_cast<uint8_t>(msg[i+j*4+1]) << 16)
                 | (static_cast<uint8_t>(msg[i+j*4+2]) <<  8)
                 |  static_cast<uint8_t>(msg[i+j*4+3]);
        }
        for (int j = 16; j < 64; ++j)
            w[j] = gam1(w[j-2]) + w[j-7] + gam0(w[j-15]) + w[j-16];

        auto [a,b,c,d,e,f,g,hh] = h;
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = hh + sig1(e) + ch(e,f,g) + K[j] + w[j];
            uint32_t t2 = sig0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1;
            d=c;  c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    std::ostringstream oss;
    for (auto v : h) oss << std::hex << std::setw(8) << std::setfill('0') << v;
    return oss.str();
}

} // namespace iskabon::utils
