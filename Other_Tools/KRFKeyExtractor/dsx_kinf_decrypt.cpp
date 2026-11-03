// dsx_kinf_decrypt.cpp -- decrypt a secure-storage map (.kinf2024).
//
// Self-contained: SHA-1 / SHA-256 / MD5 / HMAC / HKDF / AES-256-GCM are implemented here, so
// the file builds with nothing but libstdc++ (no OpenSSL needed).
#include "dsx_kinf_decrypt.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fs = ghc::filesystem;
namespace {

// ------------------------------------------------------------------ small helpers
std::string readFile(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + p.string());
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string toHex(const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 15]; }
    return s;
}

// ------------------------------------------------------------------ SHA-256
void sha256Block(uint32_t h[8], const uint8_t* p) {
    static const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t(p[4*i]) << 24) | (uint32_t(p[4*i+1]) << 16) |
               (uint32_t(p[4*i+2]) << 8) | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        const uint32_t s0 = (w[i-15] >> 7 | w[i-15] << 25) ^ (w[i-15] >> 18 | w[i-15] << 14) ^ (w[i-15] >> 3);
        const uint32_t s1 = (w[i-2] >> 17 | w[i-2] << 15) ^ (w[i-2] >> 19 | w[i-2] << 13) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],h7=h[7];
    for (int i = 0; i < 64; i++) {
        const uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = h7 + S1 + ch + K[i] + w[i];
        const uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
        const uint32_t t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
        h7=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=h7;
}

std::array<uint8_t, 32> sha256(const uint8_t* d, size_t len) {
    uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                     0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    size_t i = 0;
    for (; len - i >= 64; i += 64) sha256Block(h, d + i);
    uint8_t tail[128] = {0};
    const size_t rem = len - i;
    std::memcpy(tail, d + i, rem);
    tail[rem] = 0x80;
    const size_t total = (rem < 56) ? 64 : 128;
    const uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int k = 0; k < 8; k++) tail[total - 1 - k] = static_cast<uint8_t>(bits >> (8 * k));
    for (size_t b = 0; b < total; b += 64) sha256Block(h, tail + b);
    std::array<uint8_t, 32> out{};
    for (int k = 0; k < 8; k++)
        for (int j = 0; j < 4; j++) out[k*4+j] = static_cast<uint8_t>(h[k] >> (24 - 8*j));
    return out;
}

// ------------------------------------------------------------------ SHA-1
void sha1Block(uint32_t h[5], const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t(p[4*i]) << 24) | (uint32_t(p[4*i+1]) << 16) |
               (uint32_t(p[4*i+2]) << 8) | p[4*i+3];
    for (int i = 16; i < 80; i++) { const uint32_t t = w[i-3]^w[i-8]^w[i-14]^w[i-16]; w[i] = t << 1 | t >> 31; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);              k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d;                       k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);     k = 0x8f1bbcdcu; }
        else             { f = b ^ c ^ d;                       k = 0xca62c1d6u; }
        const uint32_t t = (a << 5 | a >> 27) + f + e + k + w[i];
        e = d; d = c; c = b << 30 | b >> 2; b = a; a = t;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
}

std::array<uint8_t, 20> sha1(const uint8_t* d, size_t len) {
    uint32_t h[5] = {0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u};
    size_t i = 0;
    for (; len - i >= 64; i += 64) sha1Block(h, d + i);
    uint8_t tail[128] = {0};
    const size_t rem = len - i;
    std::memcpy(tail, d + i, rem);
    tail[rem] = 0x80;
    const size_t total = (rem < 56) ? 64 : 128;
    const uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int k = 0; k < 8; k++) tail[total - 1 - k] = static_cast<uint8_t>(bits >> (8 * k));
    for (size_t b = 0; b < total; b += 64) sha1Block(h, tail + b);
    std::array<uint8_t, 20> out{};
    for (int k = 0; k < 5; k++)
        for (int j = 0; j < 4; j++) out[k*4+j] = static_cast<uint8_t>(h[k] >> (24 - 8*j));
    return out;
}

// ------------------------------------------------------------------ MD5
std::array<uint8_t, 16> md5(const uint8_t* d, size_t len) {
    static const uint32_t K[64] = {
        0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
        0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
        0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
        0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
        0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
        0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
        0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
        0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u,
    };
    static const int S[64] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                              5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
                              4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                              6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    uint32_t a0=0x67452301u,b0=0xefcdab89u,c0=0x98badcfeu,d0=0x10325476u;
    auto block = [&](const uint8_t* p) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++)
            M[i] = uint32_t(p[4*i]) | (uint32_t(p[4*i+1]) << 8) |
                   (uint32_t(p[4*i+2]) << 16) | (uint32_t(p[4*i+3]) << 24);
        uint32_t A=a0,B=b0,C=c0,D=d0;
        for (int i = 0; i < 64; i++) {
            uint32_t F, g;
            if (i < 16)      { F = (B & C) | (~B & D);  g = i; }
            else if (i < 32) { F = (D & B) | (~D & C);  g = (5*i + 1) & 15; }
            else if (i < 48) { F = B ^ C ^ D;           g = (3*i + 5) & 15; }
            else             { F = C ^ (B | ~D);        g = (7*i) & 15; }
            F = F + A + K[i] + M[g];
            A = D; D = C; C = B;
            B = B + ((F << S[i]) | (F >> (32 - S[i])));
        }
        a0+=A; b0+=B; c0+=C; d0+=D;
    };
    size_t i = 0;
    for (; len - i >= 64; i += 64) block(d + i);
    uint8_t tail[128] = {0};
    const size_t rem = len - i;
    std::memcpy(tail, d + i, rem);
    tail[rem] = 0x80;
    const size_t total = (rem < 56) ? 64 : 128;
    const uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int k = 0; k < 8; k++) tail[total - 8 + k] = static_cast<uint8_t>(bits >> (8 * k));
    for (size_t b = 0; b < total; b += 64) block(tail + b);
    std::array<uint8_t, 16> out{};
    const uint32_t v[4] = {a0, b0, c0, d0};
    for (int k = 0; k < 4; k++)
        for (int j = 0; j < 4; j++) out[k*4+j] = static_cast<uint8_t>(v[k] >> (8*j));
    return out;
}

// ------------------------------------------------------------------ HMAC-SHA256 / HKDF
std::vector<uint8_t> hmacSha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen) {
    uint8_t k[64] = {0};
    if (klen > 64) { const auto h = sha256(key, klen); std::memcpy(k, h.data(), 32); }
    else std::memcpy(k, key, klen);
    std::vector<uint8_t> inner(64 + mlen);
    for (size_t i = 0; i < 64; i++) inner[i] = k[i] ^ 0x36;
    std::memcpy(inner.data() + 64, msg, mlen);
    const auto ih = sha256(inner.data(), inner.size());
    uint8_t outer[96];
    for (int i = 0; i < 64; i++) outer[i] = k[i] ^ 0x5c;
    std::memcpy(outer + 64, ih.data(), 32);
    const auto oh = sha256(outer, sizeof outer);
    return std::vector<uint8_t>(oh.begin(), oh.end());
}

std::vector<uint8_t> hkdfSha256(const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& salt,
                                const std::string& info, size_t outLen) {
    const auto prk = hmacSha256(salt.data(), salt.size(), ikm.data(), ikm.size());
    std::vector<uint8_t> okm, t;
    uint8_t ctr = 1;
    while (okm.size() < outLen) {
        std::vector<uint8_t> seed = t;
        seed.insert(seed.end(), info.begin(), info.end());
        seed.push_back(ctr++);
        t = hmacSha256(prk.data(), prk.size(), seed.data(), seed.size());
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(outLen);
    return okm;
}

// ------------------------------------------------------------------ AES-256
struct Aes256 {
    uint8_t sb[256] = {0};
    uint32_t rk[60] = {0};

    Aes256() {
        // Algebraic S-box: inverse in GF(2^8) mod 0x11b, then the affine map.
        auto gmul = [](uint8_t a, uint8_t b) {
            uint8_t r = 0;
            for (int i = 0; i < 8; i++) { if (b & 1) r ^= a; const uint8_t hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b; b >>= 1; }
            return r;
        };
        for (int x = 0; x < 256; x++) {
            uint8_t inv = 0;
            if (x) { for (int y = 1; y < 256; y++) if (gmul(static_cast<uint8_t>(x), static_cast<uint8_t>(y)) == 1) { inv = static_cast<uint8_t>(y); break; } }
            else inv = 0;
            uint8_t s = inv;
            uint8_t v = inv;
            for (int i = 0; i < 4; i++) { v = static_cast<uint8_t>((v << 1) | (v >> 7)); s ^= v; }
            sb[x] = static_cast<uint8_t>(s ^ 0x63);
        }
    }

    static uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

    void setKey(const uint8_t* key) {
        static const uint8_t RCON[8] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80};
        for (int i = 0; i < 8; i++)
            rk[i] = (uint32_t(key[4*i]) << 24) | (uint32_t(key[4*i+1]) << 16) |
                    (uint32_t(key[4*i+2]) << 8) | key[4*i+3];
        for (int i = 8; i < 60; i++) {
            uint32_t t = rk[i - 1];
            auto subWord = [&](uint32_t w) {
                return (uint32_t(sb[(w >> 24) & 0xff]) << 24) | (uint32_t(sb[(w >> 16) & 0xff]) << 16) |
                       (uint32_t(sb[(w >> 8) & 0xff]) << 8) | sb[w & 0xff];
            };
            if ((i & 7) == 0)      { t = (t << 8) | (t >> 24); t = subWord(t) ^ (uint32_t(RCON[i/8 - 1]) << 24); }
            else if ((i & 7) == 4) { t = subWord(t); }
            rk[i] = rk[i - 8] ^ t;
        }
    }

    void encryptBlock(const uint8_t* in, uint8_t* out) const {
        uint8_t s[16];
        std::memcpy(s, in, 16);
        addRoundKey(s, 0);
        for (int r = 1; r <= 14; r++) {
            for (int i = 0; i < 16; i++) s[i] = sb[s[i]];
            shiftRows(s);
            if (r != 14) mixColumns(s);
            addRoundKey(s, r);
        }
        std::memcpy(out, s, 16);
    }

    static void shiftRows(uint8_t* s) {
        uint8_t t[16];
        std::memcpy(t, s, 16);
        for (int r = 1; r < 4; r++)
            for (int c = 0; c < 4; c++) s[4*c + r] = t[4*((c + r) % 4) + r];
    }
    static void mixColumns(uint8_t* s) {
        for (int c = 0; c < 4; c++) {
            const uint8_t a0=s[4*c], a1=s[4*c+1], a2=s[4*c+2], a3=s[4*c+3];
            s[4*c]   = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
            s[4*c+1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
            s[4*c+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
            s[4*c+3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        }
    }
    void addRoundKey(uint8_t* s, int r) const {
        for (int c = 0; c < 4; c++) {
            const uint32_t w = rk[r*4 + c];
            s[4*c]   ^= static_cast<uint8_t>(w >> 24);
            s[4*c+1] ^= static_cast<uint8_t>(w >> 16);
            s[4*c+2] ^= static_cast<uint8_t>(w >> 8);
            s[4*c+3] ^= static_cast<uint8_t>(w);
        }
    }
};

// ------------------------------------------------------------------ AES-256-GCM
void ghashMul(uint8_t x[16], const uint8_t y[16]) {
    uint8_t z[16] = {0}, v[16];
    std::memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
        if ((x[i / 8] >> (7 - (i % 8))) & 1) for (int j = 0; j < 16; j++) z[j] ^= v[j];
        const uint8_t lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = static_cast<uint8_t>((v[j] >> 1) | (v[j-1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    std::memcpy(x, z, 16);
}

void ghashOver(uint8_t x[16], const uint8_t H[16], const uint8_t* data, size_t len) {
    for (size_t off = 0; off < len; off += 16) {
        const size_t n = std::min<size_t>(16, len - off);
        for (size_t i = 0; i < 16; i++) x[i] ^= (i < n) ? data[off + i] : 0;
        ghashMul(x, H);
    }
}

// Returns plaintext; throws on tag mismatch. nonce is 12 bytes (the storage framing).
std::vector<uint8_t> aesGcmDecrypt(const uint8_t key[32], const uint8_t* nonce, size_t nlen,
                                   const uint8_t* ct, size_t clen, const uint8_t tag[16]) {
    if (nlen != 12) throw std::runtime_error("aesGcmDecrypt: only 12-byte nonces are used here");
    Aes256 aes;
    aes.setKey(key);
    uint8_t zero[16] = {0}, H[16];
    aes.encryptBlock(zero, H);

    uint8_t J0[16];
    std::memcpy(J0, nonce, 12);
    J0[12] = J0[13] = J0[14] = 0; J0[15] = 1;

    auto inc32 = [](uint8_t c[16]) {
        for (int i = 15; i >= 12; i--) if (++c[i]) break;
    };

    std::vector<uint8_t> pt(clen);
    uint8_t ctr[16];
    std::memcpy(ctr, J0, 16);
    inc32(ctr);
    uint8_t ks[16];
    for (size_t off = 0; off < clen; off += 16) {
        aes.encryptBlock(ctr, ks);
        inc32(ctr);
        const size_t n = std::min<size_t>(16, clen - off);
        for (size_t i = 0; i < n; i++) pt[off + i] = static_cast<uint8_t>(ct[off + i] ^ ks[i]);
    }

    uint8_t x[16] = {0};
    ghashOver(x, H, ct, clen);
    uint8_t lens[16] = {0};
    const uint64_t abits = 0, cbits = static_cast<uint64_t>(clen) * 8;
    for (int k = 0; k < 8; k++) {
        lens[7 - k]  = static_cast<uint8_t>(abits >> (8 * k));
        lens[15 - k] = static_cast<uint8_t>(cbits >> (8 * k));
    }
    ghashOver(x, H, lens, 16);

    uint8_t ek0[16];
    aes.encryptBlock(J0, ek0);
    uint8_t expect[16];
    for (int i = 0; i < 16; i++) expect[i] = static_cast<uint8_t>(x[i] ^ ek0[i]);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff = static_cast<uint8_t>(diff | (expect[i] ^ tag[i]));
    if (diff) throw std::runtime_error("GCM tag mismatch (wrong key, salt or info)");
    return pt;
}

// ------------------------------------------------------------------ ObfuscatorV1 layers
// ObfV1_F5_CaesarStrip_180129210 + marker drop.  k = len(key string) & 7 = 1 for this build.
char rot5(char c, int s) {
    if (c >= 'A' && c <= 'Z') return static_cast<char>('A' + (((c - 'A') + s) % 26 + 26) % 26);
    if (c >= 'a' && c <= 'z') return static_cast<char>('a' + (((c - 'a') + s) % 26 + 26) % 26);
    if (c >= '0' && c <= '9') return static_cast<char>('0' + (((c - '0') + s) % 10 + 10) % 10);
    return c;
}

std::string f5Strip(const std::string& rec, int k = 1) {
    std::string body(rec.rbegin(), rec.rend());
    body.erase(body.begin());                       // drop the leading marker char
    for (size_t i = 0; i < body.size(); i++)
        if (body[i] != '=') body[i] = rot5(body[i], (i % 2 == 0) ? k : -k);
    return body;
}

std::string b64Decode(const std::string& in) {
    static const std::string A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto idx = [&](char c) { return static_cast<int>(A.find(c)); };
    std::string out;
    int val = 0, bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        const int v = idx(c);
        if (v < 0) throw std::runtime_error("bad base64 char");
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out += static_cast<char>((val >> bits) & 0xff); }
    }
    return out;
}

// ObfV1_F4_Dec_180126000 -- LZW over the dumped contextMap.
std::string f4Decode(const std::vector<int>& codes) {
    std::vector<std::string> dict(256);
    for (int i = 0; i < 256; i++) dict[i] = std::string(1, static_cast<char>(i));
    std::string res;
    std::string prev;
    bool havePrev = false;
    for (int c : codes) {
        std::string e;
        if (c >= 0 && c < static_cast<int>(dict.size())) e = dict[c];
        else if (havePrev) e = prev + prev[0];
        else throw std::runtime_error("F4: unknown code with no history");
        res += e;
        if (havePrev) dict.push_back(prev + e[0]);
        prev = e;
        havePrev = true;
    }
    return res;
}

// ObfV1_F3_Dec_18012ad30 in closed form (see f3_cracked.cpp).  out[j] = in[perm[j]].
long bounce(long i, long p) { const long m = 2 * p; const long r = i % m; return (r <= p) ? r : m - r; }

std::vector<int> f3Perm(size_t L, uint32_t dwKey) {
    const long p = static_cast<long>(dwKey) - 1;
    std::vector<std::pair<long, long>> mark(L);
    for (size_t i = 0; i < L; i++) mark[i] = {bounce(static_cast<long>(i), p), static_cast<long>(i)};
    std::vector<std::pair<long, long>> wr = mark;
    std::sort(wr.begin(), wr.end());
    std::vector<int> pos(L);
    for (size_t i = 0; i < L; i++) pos[static_cast<size_t>(wr[i].second)] = static_cast<int>(i);
    std::vector<int> perm(L);
    for (size_t j = 0; j < L; j++) perm[j] = pos[static_cast<size_t>(mark[j].second)];
    return perm;
}

// ObfV1_B64Enc2_180125610 -- 7-symbol string -> bit string.
std::string b64Enc2(const std::string& s) {
    auto rank = [](char c) -> int {
        switch (c) { case 'a': return 0; case 'b': return 1; case 'c': return 2;
                     case 'd': return 3; case 'e': return 4; case 'f': return 5; default: return -1; }
    };
    std::string bits;
    size_t start = 0;
    while (start <= s.size()) {
        const size_t z = s.find('Z', start);
        const std::string tok = s.substr(start, (z == std::string::npos ? s.size() : z) - start);
        if (!tok.empty()) {
            if (tok.size() == 2 && start >= s.size() - 2)
            {
                const int r = rank(tok[0]);
                if (r < 0||tok[1]!='A') throw std::runtime_error("B64Enc2: bad symbol in last token");
                bits.append(static_cast<size_t>(r + 1), '0');
            }
            else 
            {
            if (tok.size() == 3 && tok[1] == 'A') {
                const int r0 = rank(tok[0]), r2 = rank(tok[2]);
                if (r0 < 0 || r2 < 0) throw std::runtime_error("B64Enc2: bad symbol");
                bits.append(static_cast<size_t>(r0 + 1), '0');
                bits.append(static_cast<size_t>(r2 + 1), '1');
            } else {
                const int r = rank(tok.back());
                if (r < 0) throw std::runtime_error("B64Enc2: bad symbol");
                bits.append(static_cast<size_t>(r + 1), '1');
            }
            }
        }
        if (z == std::string::npos) break;
        start = z + 1;
    }
    return bits;
}

// ObfV1_F2_Dec_180134f20 -- rotate the bit string right by n, then pack 8 bits per char.
// n is dwF2_key, which the constructor sets to dwF3_key % 5 -- it is not independent.
std::string f2Decode(const std::string& bits, uint32_t n) {
    if (bits.size() < n || bits.size() % 8 != 0)
        throw std::runtime_error("F2: bad bit length");
    const std::string rot = bits.substr(bits.size() - n) + bits.substr(0, bits.size() - n);
    std::string out;
    for (size_t i = 0; i + 8 <= rot.size(); i += 8) {
        int v = 0;
        for (int k = 0; k < 8; k++) v = (v << 1) | (rot[i + k] == '1');
        out += static_cast<char>(v);
    }
    return out;
}

// ObfV1_F1_Dec_1801296b0 -- 5-row column-major transpose; '^' means ' '.
std::string f1Decode(const std::string& s) {
    const size_t nc = static_cast<size_t>(std::count(s.begin(), s.end(), '^'));
    const size_t ncols = (s.size() - nc) / 5 + 1;
    if (ncols * 5 != s.size()) throw std::runtime_error("F1: unexpected length");
    std::string out;
    out.reserve(ncols);
    for (size_t c = 0; c < ncols; c++)
        for (size_t r = 0; r < 5; r++) {
            const char ch = s[r * ncols + c];
            out += (ch == '^') ? ' ' : ch;
        }
    return out;
}

// A64PairCodecDecodeTextToBytes_1800f8c00 (radix 0x40).
const char* const kA64Alphabet = "YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD";

std::vector<uint8_t> a64Decode(const std::string& text) {
    static const std::string A64(kA64Alphabet);
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < text.size(); i += 2) {
        const size_t hi = A64.find(text[i]);
        const size_t lo = A64.find(text[i + 1]);
        if (hi == std::string::npos || lo == std::string::npos) break;
        out.push_back(static_cast<uint8_t>(((hi * 64) ^ 0x80) + lo));
    }
    return out;
}

// ------------------------------------------------------------------ container
std::vector<std::string> splitRecords(const std::string& file) {
    const size_t hash = file.find('#');
    if (hash == std::string::npos) throw std::runtime_error("no '#' header terminator in container");
    std::vector<std::string> recs;
    size_t start = hash + 1;
    while (start <= file.size()) {
        const size_t r = file.find('}', start);
        const std::string f = file.substr(start, (r == std::string::npos ? file.size() : r) - start);
        if (!f.empty()) recs.push_back(f);
        if (r == std::string::npos) break;
        start = r + 1;
    }
    return recs;
}

struct Entry { std::string keyText; std::string valText; std::vector<uint8_t> keyMd5; std::vector<uint8_t> value; };

Entry decodeRecord(const std::string& rec, const ObfV1Keys& keys) {
    if (keys.dwF3Key == 0) throw std::runtime_error("decodeRecord: keys not initialised");
    const std::string b64 = f5Strip(rec);
    const std::string csv = b64Decode(b64);
    std::vector<int> codes;
    {
        size_t start = 0;
        while (start < csv.size()) {
            const size_t c = csv.find(',', start);
            const std::string tok = csv.substr(start, (c == std::string::npos ? csv.size() : c) - start);
            if (!tok.empty()) codes.push_back(std::stoi(tok));
            if (c == std::string::npos) break;
            start = c + 1;
        }
    }
    const std::string f4 = f4Decode(codes);
    const std::vector<int> perm = f3Perm(f4.size(), keys.dwF3Key);
    std::string f3(f4.size(), '\0');
    for (size_t i = 0; i < f4.size(); i++) f3[i] = f4[static_cast<size_t>(perm[i])];
    std::string flat = f1Decode(f2Decode(b64Enc2(f3), keys.dwF2Key));
    while (!flat.empty() && flat.back() == ' ') flat.pop_back();
    const size_t star = flat.find('*');
    if (star == std::string::npos) throw std::runtime_error("record has no KEY/VALUE separator");
    Entry e;
    e.keyText = flat.substr(0, star);
    e.valText = flat.substr(star + 1);
    e.value = a64Decode(e.valText);
    e.keyMd5 = a64Decode(e.keyText);
    if (e.keyMd5.size() != 16) throw std::runtime_error("KEY field did not decode to 16 bytes");
    return e;
}

// Cheap structural oracle used to recover dwF3_key: the KEY field is always 32 characters of
// the A64 alphabet and the VALUE only ever holds A64 characters, so a wrong dwF3_key (and with
// it a wrong dwF2_key = dwF3_key % 5) essentially never survives.
bool recordLooksValid(const std::string& rec, const ObfV1Keys& keys) {
    try {
        const Entry e = decodeRecord(rec, keys);
        if (e.keyText.size() != 32) return false;
        const std::string A(kA64Alphabet);
        for (char c : e.keyText) if (A.find(c) == std::string::npos) return false;
        for (char c : e.valText) if (A.find(c) == std::string::npos) return false;
        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace

// ------------------------------------------------------------------ public API
// ObfuscatorV1 key derivation -- SecureStorageFileObfuscatorV1Ctor_18011c5b0.
// All four keys come from one string `s`, the DECIMAL volume serial number of the volume
// holding QDir::rootPath() (GetVolumeSerialDecimalString_1810059e0), or "9999999999" when
// GetVolumeInformationW fails.

// ObfV1_DeriveF3Key_18011d230. The CFF state machine reduces to: while the string is longer
// than 5 characters, replace it by the decimal form of its byte sum, then parse it. For any
// realistic key source that single pass is the whole computation.
static uint32_t deriveF3Key(const std::string& src) {
    std::string t = src;
    while (t.size() > 5) {
        uint32_t acc = 0;
        for (char c : t) acc += static_cast<uint8_t>(c);
        t = std::to_string(acc);
    }
    uint64_t v = 0;
    for (char c : t) {
        if (c < '0' || c > '9') throw std::runtime_error("ObfuscatorV1: key source does not reduce to a number");
        v = v * 10 + static_cast<uint64_t>(c - '0');
        if (v > 0xffffffffull) throw std::runtime_error("ObfuscatorV1: dwF3_key out of range");
    }
    return static_cast<uint32_t>(v);
}

// ObfV1_DeriveF1KeyTail5_18011d8a0 -- the last 5 characters. F1_Dec only reads its length.
static std::string deriveF1KeyTail5(const std::string& src) {
    if (src.size() < 5) throw std::runtime_error("ObfuscatorV1: key source shorter than 5 characters");
    return src.substr(src.size() - 5);
}

// ObfV1_DeriveF5Key_18011cfa0 -- position-weighted byte sum, mod 8, as a decimal string.
// F5_CaesarStrip uses f5_key.size() & 7 and this is always one char, which is why the Caesar
// shift is 1 on every device. s = "236943134" gives w = 2327 -> "7".
static std::string deriveF5Key(const std::string& src) {
    uint32_t w = 0;
    for (size_t i = 0; i < src.size(); i++)
        w += static_cast<uint32_t>(static_cast<uint8_t>(src[i])) * static_cast<uint32_t>(i + 1);
    return std::to_string(w % 8);
}

ObfV1Keys obfDeriveKeys(const std::string& keySource) {
    ObfV1Keys k;
    k.keySource = keySource;
    k.f1Key   = deriveF1KeyTail5(keySource);
    k.dwF3Key = deriveF3Key(keySource);
    k.dwF2Key = k.dwF3Key % 5;
    k.f5Key   = deriveF5Key(keySource);
    return k;
}

ObfV1Keys obfKeysFromVolumeSerial(uint32_t serial) {
    return obfDeriveKeys(std::to_string(serial));   // "%u": decimal, exactly as the binary does it
}

ObfV1Keys obfKeysFromDwKey(uint32_t dwF3Key) {
    ObfV1Keys k;
    k.dwF3Key = dwF3Key;
    k.dwF2Key = dwF3Key % 5;
    k.f1Key.assign(5, '0');   // only f1Key.size() is consumed by F1_Dec
    k.f5Key = "0";            // only f5Key.size() is consumed by F5_CaesarStrip
    return k;
}

ObfV1Keys kinf2024RecoverKeys(const std::vector<std::string>& records) {
    // s is a decimal digit string of 1..10 characters, so dwF3_key = sum(bytes) is confined to
    // 48..570 and dwF2_key is then fixed at dwF3_key % 5: 523 candidates. On a real container
    // the record structure leaves exactly one standing, and one record is already enough.
    const size_t n = records.size() < 4 ? records.size() : 4;
    for (uint32_t k = 48; k <= 570; k++) {
        const ObfV1Keys keys = obfKeysFromDwKey(k);
        bool all = true;
        for (size_t i = 0; i < n; i++) 
        {
            if (!recordLooksValid(records[i], keys)) { all = false; break; }

        }
        if (all) 
        {
            printf("Serial sum %d seems to match\n",k);
            return keys;
        }
    }
    throw std::runtime_error("could not recover the ObfuscatorV1 dwF3_key from the container; "
                             "pass the volume serial explicitly");
}

ObfV1Keys kinf2024KeysForFile(const fs::path& kinfPath, uint32_t serial) {
    if (serial) return obfKeysFromVolumeSerial(serial);
    return kinf2024RecoverKeys(splitRecords(readFile(kinfPath)));
}

std::string md5Hex(const std::string& s) {
    const auto h = md5(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    return toHex(h.data(), h.size());
}

std::vector<uint8_t> storageIkm(const std::vector<uint8_t>& master32, const fs::path& saltFile) {
    if (master32.size() != 32) throw std::runtime_error("master32 must be 32 bytes");
    const std::string salt = readFile(saltFile);
    // SSEV2EncryptEntryValue_18010b6f0: HKDF-SHA256(master32, main_shared.salt, "kindle_ss")
    return hkdfSha256(master32, std::vector<uint8_t>(salt.begin(), salt.end()), "kindle_ss", 32);
}

std::map<std::string, std::string> decryptKinStorage(const fs::path& kinfPath,
                                                     const fs::path& saltFile,
                                                     const std::vector<uint8_t>& master32,
                                                     uint32_t serial) {
    const std::string file = readFile(kinfPath);
    // The F3/F2 keys are device-specific (they come from the volume serial), so take them from
    // the caller when the serial is known and otherwise recover them from the records.
    const ObfV1Keys keys = serial ? obfKeysFromVolumeSerial(serial)
                                  : kinf2024RecoverKeys(splitRecords(file));
    return decryptKinStorage(kinfPath, saltFile, master32, keys);
}

std::map<std::string, std::string> decryptKinStorage(const fs::path& kinfPath,
                                                     const fs::path& saltFile,
                                                     const std::vector<uint8_t>& master32,
                                                     const ObfV1Keys& keys) {
    const std::vector<uint8_t> ikm = storageIkm(master32, saltFile);
    const std::string file = readFile(kinfPath);
    std::map<std::string, std::string> out;
    for (const std::string& rec : splitRecords(file)) {
        const Entry e = decodeRecord(rec, keys);
        if (e.value.size() < 28) throw std::runtime_error("VALUE shorter than nonce+tag");
        // SSEV2DeriveEntryKey_18010bfa0: salt = SHA1(KEY text), info = "kindle_ss_token"
        const auto s1 = sha1(reinterpret_cast<const uint8_t*>(e.keyText.data()), e.keyText.size());
        const std::vector<uint8_t> salt(s1.begin(), s1.end());
        const std::vector<uint8_t> key32 = hkdfSha256(ikm, salt, "kindle_ss_token", 32);
        const std::vector<uint8_t> pt = aesGcmDecrypt(
            key32.data(), e.value.data(), 12,
            e.value.data() + 12, e.value.size() - 28, e.value.data() + e.value.size() - 16);
        out[toHex(e.keyMd5.data(), 16)] = std::string(pt.begin(), pt.end());
    }
    return out;
}

