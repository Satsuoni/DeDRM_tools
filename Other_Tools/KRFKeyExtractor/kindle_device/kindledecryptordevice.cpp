//#define _GLIBCXX_USE_CXX11_ABI 0
#define _FILE_OFFSET_BITS 64
#include "miniz.h" //https://github.com/richgel999/miniz/releases
#include "plthook.h"
#include <dlfcn.h>
#include <fcntl.h>
#include "filesystem.hpp"
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <algorithm>
#include <execinfo.h>
#define POCKETLZMA_LZMA_C_DEFINE
#include "plusaes.hpp" //https://github.com/kkAyataka/plusaes/releases
#include "pocketlzma.hpp" //https://github.com/SSBMTonberry/pocketlzma ,but needs fixing, in decompress, replace (value << (i * 8)); with ((size_t)value << (i * 8));
#include "json.hpp"

#ifndef UCHAR
#define UCHAR unsigned char
#endif

namespace fs = ghc::filesystem;
using json=nlohmann::json;

std::vector<char> sha1_from_scratch(const std::vector<char>& input) {
    // 1. Initialize variables (RFC 3174 constants)
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // 2. Padding logic
    std::vector<uint8_t> padded(input.begin(), input.end());
    uint64_t orig_bit_len = static_cast<uint64_t>(input.size()) * 8;

    // Append the '1' bit as a byte
    padded.push_back(0x80);

    // Append '0' bits until message length % 512 is congruent to 448 bits
    while ((padded.size() * 8) % 512 != 448) {
        padded.push_back(0x00);
    }

    // Append the original bit length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>((orig_bit_len >> (i * 8)) & 0xFF));
    }

    // 3. Process the message in successive 512-bit (64-byte) chunks
    for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
        uint32_t w[80] = {0};

        // Break chunk into sixteen 32-bit big-endian words
        for (int t = 0; t < 16; ++t) {
            size_t idx = chunk + (t * 4);
            w[t] = (static_cast<uint32_t>(padded[idx]) << 24) |
                   (static_cast<uint32_t>(padded[idx + 1]) << 16) |
                   (static_cast<uint32_t>(padded[idx + 2]) << 8) |
                   (static_cast<uint32_t>(padded[idx + 3]));
        }

        // Extend the sixteen 32-bit words into eighty 32-bit words
        for (int t = 16; t < 80; ++t) {
            uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (val << 1) | (val >> 31); // Left rotate by 1
        }

        // Initialize hash value for this chunk
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        // Main loop (80 operations)
        for (int t = 0; t < 80; ++t) {
            uint32_t f, k;

            if (t <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2); // Left rotate by 30
            b = a;
            a = temp;
        }

        // Add this chunk's hash to the total result
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // 4. Produce final output vector (20 bytes total)
    std::vector<char> output;
    output.reserve(20);
    uint32_t hashes[5] = {h0, h1, h2, h3, h4};

    for (int i = 0; i < 5; ++i) {
        output.push_back(static_cast<char>((hashes[i] >> 24) & 0xFF));
        output.push_back(static_cast<char>((hashes[i] >> 16) & 0xFF));
        output.push_back(static_cast<char>((hashes[i] >> 8) & 0xFF));
        output.push_back(static_cast<char>(hashes[i] & 0xFF));
    }

    return output;
}
//MD5, complete with license
/*
MD5 hashing. Choice of public domain or MIT-0. See license statements at the end of this file.

David Reid - mackron@gmail.com
*/

/*
A simple MD5 hashing implementation. Usage:

    unsigned char digest[MD5_SIZE];
    md5_context ctx;
    md5_init(&ctx);
    {
        md5_update(&ctx, src, sz);
    }
    md5_finalize(&ctx, digest);

The above code is the literal implementation of `md5()` which is a high level helper for hashing
data of a known size:

    unsigned char hash[MD5_SIZE];
    md5(hash, data, dataSize);

Use `md5_format()` to format the digest as a hex string. The capacity of the output buffer needs to
be at least `MD5_SIZE_FORMATTED` bytes.

This library does not perform any memory allocations and does not use anything from the standard
library except for `size_t` and `NULL`, both of which are drawn in from stddef.h. No other standard
headers are included.

There is no need to link to anything with this library. You can use MD5_IMPLEMENTATION to define
the implementation section, or you can use md5.c if you prefer a traditional header/source pair.
*/
#define MD5_IMPLEMENTATION  1
#ifndef md5_h
#define md5_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h> /* For size_t and NULL. */

#if defined(_MSC_VER)
    typedef unsigned __int64   md5_uint64;
#else
    typedef unsigned long long md5_uint64;
#endif

#if !defined(MD5_API)
    #define MD5_API
#endif

#define MD5_SIZE            16
#define MD5_SIZE_FORMATTED  33

typedef struct
{
    unsigned int a, b, c, d;    /* Registers. RFC 1321 section 3.3. */
    md5_uint64 sz;              /* 64-bit size. Since this is library operates on bytes, this is a byte count rather than a bit count. */
    unsigned char cache[64];    /* The cache will be filled with data, and when full will be processed. */
    unsigned int cacheLen;      /* Number of valid bytes in the cache. */
} md5_context;

MD5_API void md5_init(md5_context* ctx);
MD5_API void md5_update(md5_context* ctx, const void* src, size_t sz);
MD5_API void md5_finalize(md5_context* ctx, unsigned char* digest);
MD5_API void md5(unsigned char* digest, const void* src, size_t sz);
MD5_API void md5_format(char* dst, size_t dstCap, const unsigned char* hash);

#ifdef __cplusplus
}
#endif
#endif  /* md5_h */

#if defined(MD5_IMPLEMENTATION)
#ifndef md5_c
#define md5_c

static void md5_zero_memory(void* p, size_t sz)
{
    size_t i;
    for (i = 0; i < sz; i += 1) {
        ((unsigned char*)p)[i] = 0;
    }
}

static void md5_copy_memory(void* dst, const void* src, size_t sz)
{
    size_t i;
    for (i = 0; i < sz; i += 1) {
        ((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
    }
}


/* RFC 1321 - Section 3.4. */
#define MD5_F(x, y, z) ((x & y) | (~x &  z))
#define MD5_G(x, y, z) ((x & z) | ( y & ~z))
#define MD5_H(x, y, z) (x ^ y ^ z)
#define MD5_I(x, y, z) (y ^ (x | ~z))

/*
RFC 1321 - Section 2.

    Let X <<< s denote the 32-bit value obtained by circularly shifting (rotating) X left by s bit positions.
*/
#define MD5_ROTATE_LEFT(x, n)   (((x) << (n)) | ((x) >> (32 - (n))))

/*
From appendix in RFC 1321.
*/
#define MD5_FF(a, b, c, d, x, s, ac)                        \
    (a) += MD5_F((b), (c), (d)) + (x) + (unsigned int)(ac), \
    (a)  = MD5_ROTATE_LEFT((a), (s)),                       \
    (a) += (b)

#define MD5_GG(a, b, c, d, x, s, ac)                        \
    (a) += MD5_G((b), (c), (d)) + (x) + (unsigned int)(ac), \
    (a)  = MD5_ROTATE_LEFT((a), (s)),                       \
    (a) += (b)

#define MD5_HH(a, b, c, d, x, s, ac)                        \
    (a) += MD5_H((b), (c), (d)) + (x) + (unsigned int)(ac), \
    (a)  = MD5_ROTATE_LEFT((a), (s)),                       \
    (a) += (b)

#define MD5_II(a, b, c, d, x, s, ac)                        \
    (a) += MD5_I((b), (c), (d)) + (x) + (unsigned int)(ac), \
    (a)  = MD5_ROTATE_LEFT((a), (s)),                       \
    (a) += (b)

#define MD5_S11 7
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

static void md5_decode(unsigned int* x, const unsigned char* src)
{
    size_t i, j;

    for (i = 0, j = 0; i < 16; i += 1, j += 4) {
        x[i] = ((unsigned int)src[j+0]) | (((unsigned int)src[j+1]) << 8) | (((unsigned int)src[j+2]) << 16) | (((unsigned int)src[j+3]) << 24);
    }
}

/*
This is the main MD5 function. Everything is processed in blocks of 64 bytes.
*/
static void md5_update_block(md5_context* ctx, const unsigned char* src)
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    unsigned int x[16];

    /* assert(ctx != NULL); */
    /* assert(src != NULL); */

    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;

    md5_decode(x, src);

    MD5_FF(a, b, c, d, x[ 0], MD5_S11, 0xd76aa478);
    MD5_FF(d, a, b, c, x[ 1], MD5_S12, 0xe8c7b756);
    MD5_FF(c, d, a, b, x[ 2], MD5_S13, 0x242070db);
    MD5_FF(b, c, d, a, x[ 3], MD5_S14, 0xc1bdceee);
    MD5_FF(a, b, c, d, x[ 4], MD5_S11, 0xf57c0faf);
    MD5_FF(d, a, b, c, x[ 5], MD5_S12, 0x4787c62a);
    MD5_FF(c, d, a, b, x[ 6], MD5_S13, 0xa8304613);
    MD5_FF(b, c, d, a, x[ 7], MD5_S14, 0xfd469501);
    MD5_FF(a, b, c, d, x[ 8], MD5_S11, 0x698098d8);
    MD5_FF(d, a, b, c, x[ 9], MD5_S12, 0x8b44f7af);
    MD5_FF(c, d, a, b, x[10], MD5_S13, 0xffff5bb1);
    MD5_FF(b, c, d, a, x[11], MD5_S14, 0x895cd7be);
    MD5_FF(a, b, c, d, x[12], MD5_S11, 0x6b901122);
    MD5_FF(d, a, b, c, x[13], MD5_S12, 0xfd987193);
    MD5_FF(c, d, a, b, x[14], MD5_S13, 0xa679438e);
    MD5_FF(b, c, d, a, x[15], MD5_S14, 0x49b40821);

    MD5_GG(a, b, c, d, x[ 1], MD5_S21, 0xf61e2562);
    MD5_GG(d, a, b, c, x[ 6], MD5_S22, 0xc040b340);
    MD5_GG(c, d, a, b, x[11], MD5_S23, 0x265e5a51);
    MD5_GG(b, c, d, a, x[ 0], MD5_S24, 0xe9b6c7aa);
    MD5_GG(a, b, c, d, x[ 5], MD5_S21, 0xd62f105d);
    MD5_GG(d, a, b, c, x[10], MD5_S22, 0x02441453);
    MD5_GG(c, d, a, b, x[15], MD5_S23, 0xd8a1e681);
    MD5_GG(b, c, d, a, x[ 4], MD5_S24, 0xe7d3fbc8);
    MD5_GG(a, b, c, d, x[ 9], MD5_S21, 0x21e1cde6);
    MD5_GG(d, a, b, c, x[14], MD5_S22, 0xc33707d6);
    MD5_GG(c, d, a, b, x[ 3], MD5_S23, 0xf4d50d87);
    MD5_GG(b, c, d, a, x[ 8], MD5_S24, 0x455a14ed);
    MD5_GG(a, b, c, d, x[13], MD5_S21, 0xa9e3e905);
    MD5_GG(d, a, b, c, x[ 2], MD5_S22, 0xfcefa3f8);
    MD5_GG(c, d, a, b, x[ 7], MD5_S23, 0x676f02d9);
    MD5_GG(b, c, d, a, x[12], MD5_S24, 0x8d2a4c8a);

    MD5_HH(a, b, c, d, x[ 5], MD5_S31, 0xfffa3942);
    MD5_HH(d, a, b, c, x[ 8], MD5_S32, 0x8771f681);
    MD5_HH(c, d, a, b, x[11], MD5_S33, 0x6d9d6122);
    MD5_HH(b, c, d, a, x[14], MD5_S34, 0xfde5380c);
    MD5_HH(a, b, c, d, x[ 1], MD5_S31, 0xa4beea44);
    MD5_HH(d, a, b, c, x[ 4], MD5_S32, 0x4bdecfa9);
    MD5_HH(c, d, a, b, x[ 7], MD5_S33, 0xf6bb4b60);
    MD5_HH(b, c, d, a, x[10], MD5_S34, 0xbebfbc70);
    MD5_HH(a, b, c, d, x[13], MD5_S31, 0x289b7ec6);
    MD5_HH(d, a, b, c, x[ 0], MD5_S32, 0xeaa127fa);
    MD5_HH(c, d, a, b, x[ 3], MD5_S33, 0xd4ef3085);
    MD5_HH(b, c, d, a, x[ 6], MD5_S34, 0x04881d05);
    MD5_HH(a, b, c, d, x[ 9], MD5_S31, 0xd9d4d039);
    MD5_HH(d, a, b, c, x[12], MD5_S32, 0xe6db99e5);
    MD5_HH(c, d, a, b, x[15], MD5_S33, 0x1fa27cf8);
    MD5_HH(b, c, d, a, x[ 2], MD5_S34, 0xc4ac5665);

    MD5_II(a, b, c, d, x[ 0], MD5_S41, 0xf4292244);
    MD5_II(d, a, b, c, x[ 7], MD5_S42, 0x432aff97);
    MD5_II(c, d, a, b, x[14], MD5_S43, 0xab9423a7);
    MD5_II(b, c, d, a, x[ 5], MD5_S44, 0xfc93a039);
    MD5_II(a, b, c, d, x[12], MD5_S41, 0x655b59c3);
    MD5_II(d, a, b, c, x[ 3], MD5_S42, 0x8f0ccc92);
    MD5_II(c, d, a, b, x[10], MD5_S43, 0xffeff47d);
    MD5_II(b, c, d, a, x[ 1], MD5_S44, 0x85845dd1);
    MD5_II(a, b, c, d, x[ 8], MD5_S41, 0x6fa87e4f);
    MD5_II(d, a, b, c, x[15], MD5_S42, 0xfe2ce6e0);
    MD5_II(c, d, a, b, x[ 6], MD5_S43, 0xa3014314);
    MD5_II(b, c, d, a, x[13], MD5_S44, 0x4e0811a1);
    MD5_II(a, b, c, d, x[ 4], MD5_S41, 0xf7537e82);
    MD5_II(d, a, b, c, x[11], MD5_S42, 0xbd3af235);
    MD5_II(c, d, a, b, x[ 2], MD5_S43, 0x2ad7d2bb);
    MD5_II(b, c, d, a, x[ 9], MD5_S44, 0xeb86d391);

    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
    
    /* We'll only ever be calling this if the context's cache is full. At this point the cache will also be empty. */
    ctx->cacheLen = 0;
}

MD5_API void md5_init(md5_context* ctx)
{
    if (ctx == NULL) {
        return;
    }

    md5_zero_memory(ctx, sizeof(*ctx));

    /* RFC 1321 - Section 3.3. */
    ctx->a  = 0x67452301;
    ctx->b  = 0xefcdab89;
    ctx->c  = 0x98badcfe;
    ctx->d  = 0x10325476;
    ctx->sz = 0;
}

MD5_API void md5_update(md5_context* ctx, const void* src, size_t sz)
{
    const unsigned char* bytes = (const unsigned char*)src;
    size_t totalBytesProcessed = 0;

    if (ctx == NULL || (src == NULL && sz > 0)) {
        return;
    }

    /* Keep processing until all data has been exhausted. */
    while (totalBytesProcessed < sz) {
        /* Optimization. Bypass the cache if there's nothing in it and the number of bytes remaining to process is larger than 64. */
        size_t bytesRemainingToProcess = sz - totalBytesProcessed;
        if (ctx->cacheLen == 0 && bytesRemainingToProcess > sizeof(ctx->cache)) {
            /* Fast path. Bypass the cache and just process directly. */
            md5_update_block(ctx, bytes + totalBytesProcessed);
            totalBytesProcessed += sizeof(ctx->cache);
        } else {
            /* Slow path. Need to store in the cache. */
            size_t cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
            if (cacheRemaining > 0) {
                /* There's still some room left in the cache. Write as much data to it as we can. */
                size_t bytesToProcess = bytesRemainingToProcess;
                if (bytesToProcess > cacheRemaining) {
                    bytesToProcess = cacheRemaining;
                }

                md5_copy_memory(ctx->cache + ctx->cacheLen, bytes + totalBytesProcessed, bytesToProcess);
                ctx->cacheLen       += (unsigned int)bytesToProcess;    /* Safe cast. bytesToProcess will always be <= sizeof(ctx->cache) which is 64. */
                totalBytesProcessed +=               bytesToProcess;

                /* Update the number of bytes remaining in the cache so we can use it later. */
                cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
            }

            /* If the cache is full, get it processed. */
            if (cacheRemaining == 0) {
                md5_update_block(ctx, ctx->cache);
            }
        }
    }

    ctx->sz += sz;
}

MD5_API void md5_finalize(md5_context* ctx, unsigned char* digest)
{
    size_t cacheRemaining;
    unsigned int szLo;
    unsigned int szHi;

    if (digest == NULL) {
        return;
    }

    if (ctx == NULL) {
        md5_zero_memory(digest, MD5_SIZE);
        return;
    }

    /*
    Padding must be applied. First thing to do is clear the cache if there's no room for at least
    one byte. This should never happen, but leaving this logic here for safety.
    */
    cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
    if (cacheRemaining == 0) {
        md5_update_block(ctx, ctx->cache);
    }

    /* Now we need to write a byte with the most significant bit set (0x80). */
    ctx->cache[ctx->cacheLen] = 0x80;
    ctx->cacheLen += 1;

    /* If there isn't enough room for 8 bytes we need to padd with zeroes and get the block processed. */
    cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
    if (cacheRemaining < 8) {
        md5_zero_memory(ctx->cache + ctx->cacheLen, cacheRemaining);
        md5_update_block(ctx, ctx->cache);
        cacheRemaining = sizeof(ctx->cache);
    }
    
    /* Now we need to fill the buffer with zeros until we've filled 56 bytes (8 bytes left over for the length). */
    md5_zero_memory(ctx->cache + ctx->cacheLen, cacheRemaining - 8);

    szLo = (unsigned int)(((ctx->sz >>  0) & 0xFFFFFFFF) << 3);
    szHi = (unsigned int)(((ctx->sz >> 32) & 0xFFFFFFFF) << 3);
    ctx->cache[56] = (unsigned char)((szLo >>  0) & 0xFF);
    ctx->cache[57] = (unsigned char)((szLo >>  8) & 0xFF);
    ctx->cache[58] = (unsigned char)((szLo >> 16) & 0xFF);
    ctx->cache[59] = (unsigned char)((szLo >> 24) & 0xFF);
    ctx->cache[60] = (unsigned char)((szHi >>  0) & 0xFF);
    ctx->cache[61] = (unsigned char)((szHi >>  8) & 0xFF);
    ctx->cache[62] = (unsigned char)((szHi >> 16) & 0xFF);
    ctx->cache[63] = (unsigned char)((szHi >> 24) & 0xFF);
    md5_update_block(ctx, ctx->cache);

    /* Now write out the digest. */
    digest[ 0] = (unsigned char)(ctx->a >> 0); digest[ 1] = (unsigned char)(ctx->a >> 8); digest[ 2] = (unsigned char)(ctx->a >> 16); digest[ 3] = (unsigned char)(ctx->a >> 24);
    digest[ 4] = (unsigned char)(ctx->b >> 0); digest[ 5] = (unsigned char)(ctx->b >> 8); digest[ 6] = (unsigned char)(ctx->b >> 16); digest[ 7] = (unsigned char)(ctx->b >> 24);
    digest[ 8] = (unsigned char)(ctx->c >> 0); digest[ 9] = (unsigned char)(ctx->c >> 8); digest[10] = (unsigned char)(ctx->c >> 16); digest[11] = (unsigned char)(ctx->c >> 24);
    digest[12] = (unsigned char)(ctx->d >> 0); digest[13] = (unsigned char)(ctx->d >> 8); digest[14] = (unsigned char)(ctx->d >> 16); digest[15] = (unsigned char)(ctx->d >> 24);
}

MD5_API void md5(unsigned char* digest, const void* src, size_t sz)
{
    md5_context ctx;
    md5_init(&ctx);
    {
        md5_update(&ctx, src, sz);
    }
    md5_finalize(&ctx, digest);
}


static void md5_format_byte(char* dst, unsigned char byte)
{
    const char* hex = "0123456789abcdef";
    dst[0] = hex[(byte & 0xF0) >> 4];
    dst[1] = hex[(byte & 0x0F)     ];
}

MD5_API void md5_format(char* dst, size_t dstCap, const unsigned char* hash)
{
    size_t i;

    if (dst == NULL) {
        return;
    }

    if (dstCap < MD5_SIZE_FORMATTED) {
        if (dstCap > 0) {
            dst[0] = '\0';
        }

        return;
    }

    for (i = 0; i < MD5_SIZE; i += 1) {
        md5_format_byte(dst + (i*2), hash[i]);
    }

    /* Always null terminate. */
    dst[MD5_SIZE_FORMATTED-1] = '\0';
}
#endif  /* md5_c */
#endif  /* MD5_IMPLEMENTATION */

/*
This software is available as a choice of the following licenses. Choose
whichever you prefer.

===============================================================================
ALTERNATIVE 1 - Public Domain (www.unlicense.org)
===============================================================================
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>

===============================================================================
ALTERNATIVE 2 - MIT No Attribution
===============================================================================
Copyright 2022 David Reid

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            std::not1(std::ptr_fun<int, int>(std::isspace))));
}

// Trim from the end (in place)
inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
}


inline void trim(std::string &s) {
    rtrim(s);
    ltrim(s);
}

void remove_non_alphanumeric(std::string& str) {
    str.erase(
        std::remove_if(str.begin(), str.end(), [](unsigned char c) {
            return !std::isalnum(c);
        }), 
        str.end()
    );
}

static std::string hexStr(const uint8_t *data, int len)
{

  char* buffer=new char[len*2+1]; 
  
  int snprintf(char *str, size_t size, const char *format, ...);
  for (int i(0); i < len; ++i)
  {
    snprintf(&buffer[i*2],3,"%02x",(int)data[i]);
  }
  std::string ret(buffer,len*2);
  return ret;
}

//--------------------------------------- ION reader

const uint8_t TID_NULL = 0;
const uint8_t TID_BOOLEAN = 1;
const uint8_t TID_POSINT = 2;
const uint8_t TID_NEGINT = 3;
const uint8_t TID_FLOAT = 4;
const uint8_t TID_DECIMAL = 5;
const uint8_t TID_TIMESTAMP = 6;
const uint8_t TID_SYMBOL = 7;
const uint8_t TID_STRING = 8;
const uint8_t TID_CLOB = 9;
const uint8_t TID_BLOB = 0xA;
const uint8_t TID_LIST = 0xB;
const uint8_t TID_SEXP = 0xC;
const uint8_t TID_STRUCT = 0xD;
const uint8_t TID_TYPEDECL = 0xE;
// const uint8_t TID_UNUSED = 0xF;

const int SID_UNKNOWN = -1;
const int SID_ION = 1;
const int SID_ION_1_0 = 2;
const int SID_ION_SYMBOL_TABLE = 3;
const int SID_NAME = 4;
const int SID_VERSION = 5;
const int SID_IMPORTS = 6;
const int SID_SYMBOLS = 7;
const int SID_MAX_ID = 8;
const int SID_ION_SHARED_SYMBOL_TABLE = 9;
const int SID_ION_1_0_MAX = 10;

const uint8_t LEN_IS_VAR_LEN = 0xE;
const uint8_t LEN_IS_NULL = 0xF;

const uint8_t VERSION_MARKER[3] = {(uint8_t)0x01, (uint8_t)0x00, (uint8_t)0xEA};

struct IonCatalogItem
{
  std::string name = "";
  int version = 0;
  std::vector<std::string> symnames;
  IonCatalogItem(const std::string &nm, int ver, const std::vector<std::string> &snames)
  {
    name = nm;
    version = ver;
    symnames = snames;
  }
};
struct SymbolToken
{
  std::string text;
  int sid = 0;
  SymbolToken(const std::string &txt, int sd)
  {
    text = txt;
    sid = sd;
    if (txt.empty() && sid == 0)
    {
      std::cerr << "SymbolToken must have text or sid " << std::endl;
    }
  }
};

const char *SystemSymbols_ION = "$ion";
const char *SystemSymbols_ION_1_0 = "$ion_1_0";
const char *SystemSymbols_ION_SYMBOL_TABLE = "$ion_symbol_table";
const char *SystemSymbols_NAME = "name";
const char *SystemSymbols_VERSION = "version";
const char *SystemSymbols_IMPORTS = "imports";
const char *SystemSymbols_SYMBOLS = "symbols";
const char *SystemSymbols_MAX_ID = "max_id";
const char *SystemSymbols_ION_SHARED_SYMBOL_TABLE = "$ion_shared_symbol_table";

struct SymbolTable
{
  std::vector<std::string> table;
  SymbolTable()
  {
    table.resize(SID_ION_1_0_MAX, "");
    table[SID_ION] = SystemSymbols_ION;
    table[SID_ION_1_0] = SystemSymbols_ION_1_0;
    table[SID_ION_SYMBOL_TABLE] = SystemSymbols_ION_SYMBOL_TABLE;
    table[SID_NAME] = SystemSymbols_NAME;
    table[SID_VERSION] = SystemSymbols_VERSION;
    table[SID_IMPORTS] = SystemSymbols_IMPORTS;
    table[SID_SYMBOLS] = SystemSymbols_SYMBOLS;
    table[SID_MAX_ID] = SystemSymbols_MAX_ID;
    table[SID_ION_SHARED_SYMBOL_TABLE] = SystemSymbols_ION_SHARED_SYMBOL_TABLE;
  }
  std::string findbyid(int sid)
  {
    if (sid < 1)
    {
      std::cerr << "Invalid SID " << sid << std::endl;
      return "";
    }
    if ((unsigned int)sid < table.size())
    {
      return table[sid];
    }
    return "";
  }
  void import_(const std::vector<std::string> &stable, size_t maxid)
  {
    maxid = (stable.size() < maxid) ? stable.size() : maxid;
    for (size_t i = 0; i < maxid; i++)
    {
      table.push_back(stable[i]);
    }
  }
  void importunknown(const std::string &name, size_t maxid)
  {
    for (size_t i = 0; i < maxid; i++)
    {
      std::ostringstream s;
      s << name << (i + 1);
      std::string query(s.str());
      table.push_back(s.str());
    }
  }
};

enum ParserState
{
  None = 0,
  Invalid = 1,
  BeforeField = 2,
  BeforeTID = 3,
  BeforeValue = 4,
  AfterValue = 5,
  EOFF = 6
};

struct ContainerRec
{
  int nextpos;
  int tid;
  int remaining;
  ContainerRec(int n, int t, int r)
  {
    nextpos = n;
    tid = t;
    remaining = r;
  }
};
enum class IonVtype
{
  None = 0,
  String = 1,
  Integer = 2,
  LongInt = 3,
  Vector = 4
};
struct IonValue
{
};
struct BinaryIonParser
{
  bool eof = false;
  ParserState state = None;
  int localremaining = 0;
  bool needhasnext = false;
  bool isinstruct = false;
  int valuetid = 0;
  int valuefieldid = 0;
  int parenttid = 0;
  int valuelen = 0;
  bool valueisnull = false;
  bool valueistrue = false;
  IonVtype vtype = IonVtype::None;
  std::string sval = "";
  int ival = 0;
  long long int lval = 0;
  std::vector<uint8_t> vec;
  void assignIonValue() {}
  void assignIonValue(const std::string &v)
  {
    valueisnull = false;
    vtype = IonVtype::String;
    sval = v;
  }
  void assignIonValue(const std::vector<uint8_t> &v)
  {
    valueisnull = false;
    vtype = IonVtype::Vector;
    vec = v;
  }
  void assignIonValue(int v)
  {
    valueisnull = false;
    vtype = IonVtype::Integer;
    ival = v;
  }
  void assignIonValue(long long int v)
  {
    valueisnull = false;
    vtype = IonVtype::LongInt;
    lval = v;
  }
  bool didimports = false;
  std::vector<int> annotations;
  std::vector<IonCatalogItem> catalog;
  SymbolTable symbols;
  std::vector<ContainerRec> containerstack;
  uint8_t *stream;
  size_t maxstrlen;
  size_t stream_pos;
  bool readerr = false;
  int eFTid = -1;
  BinaryIonParser(uint8_t *stream, size_t maxlen, int enforceFirstTid)
  {
    this->stream = stream;
    maxstrlen = maxlen;
    stream_pos = 0;
    eFTid = enforceFirstTid;
    reset();
  }
  void resetFor(uint8_t *stream, size_t maxlen)
  {
    this->stream = stream;
    maxstrlen = maxlen;
    stream_pos = 0;
    reset();
    clearvalue();
  }
  void reset()
  {
    state = ParserState::BeforeTID;
    needhasnext = true;
    localremaining = -1;
    eof = false;
    isinstruct = false;
    containerstack.clear();
    stream_pos = 0;
  }
  void addtocatalog(const std::string &name, int ver, const std::vector<std::string> &snames)
  {
    catalog.push_back(IonCatalogItem(name, ver, snames));
  }
  void clearvalue()
  {
    valuetid = -1;
    vtype = IonVtype::None;
    valueisnull = false;
    valuefieldid = SID_UNKNOWN;
    annotations.clear();
    // readerr = false;
  }
  int readfieldid()
  {
    if (readerr) return -1;
    // readerr = false;
    if (localremaining != -1 && localremaining < 1) return -1;
    int ret = readvaruint();
    if (readerr) return -1;
    return ret;
  }
  uint8_t *read() { return read(1); }
  uint8_t *read(int count)
  {
    // std::cout << " Reading " << (int)stream << " at " << stream_pos << " len: " << count << " localrem: "<< localremaining <<std::endl;
    if (localremaining != -1)
    {
      localremaining -= count;
      if (localremaining < 0)
      {
        readerr = true;
        return nullptr;
      }
    }
    uint8_t *res = &stream[stream_pos];
    stream_pos += count;
    if (stream_pos > maxstrlen)
    {
      eof = true;
      readerr = true;
      return nullptr;
    }
    return res;
  }
  int readvarint()
  {
    if (readerr) return 0;
    uint8_t *r = read();
    if (readerr) return 0;
    uint8_t b = r[0];
    bool negative = ((b & 0x40) != 0);
    int result = b & 0x3F;
    int i = 0;
    while ((b & 0x80) == 0 && i < 4)
    {
      r = read();
      b = r[0];
      if (readerr) return 0;
      result = (result << 7) | (b & 0x7F);
      i++;
    }
    if (!(i < 4 || (r[0] & 0x80) != 0))
    {
      readerr = true;
      return 0;
    }
    if (negative) return -result;
    return result;
  }
  unsigned int readvaruint()
  {
    if (readerr) return 0;
    // std::cout << hexStr(&stream[stream_pos], 4) << std::endl;
    uint8_t *r = read();
    if (readerr) return 0;
    uint8_t b = r[0];
    int result = b & 0x7F;
    int i = 0;
    while ((b & 0x80) == 0 && i < 4)
    {
      r = read();
      b = r[0];
      if (readerr) return 0;
      result = (result << 7) | (b & 0x7F);
      i++;
    }
    if (!(i < 4 || (r[0] & 0x80) != 0))
    {
      readerr = true;
      return 0;
    }
    return result;
  }

  void push(int tpid, int nxtpos, int nxtrem) { containerstack.push_back(ContainerRec(nxtpos, tpid, nxtrem)); }
  void skip(int count) { read(count); }

  bool hasnextraw()
  {
    if (readerr) return false;
    clearvalue();
    while (valuetid == -1 && !eof)
    {
      needhasnext = false;
      switch (state)
      {
      case ParserState::BeforeField:
      {
        if (valuefieldid != SID_UNKNOWN) return false;
        valuefieldid = readfieldid();
        if (valuefieldid != SID_UNKNOWN) state = ParserState::BeforeTID;
        else
        {
          eof = true;
        }
      };
      break;
      case ParserState::BeforeTID:
      {
        state = ParserState::BeforeValue;
        // std::cout << "Getting tid " << std::endl;
        valuetid = readtypeid();
        if (readerr) valuetid = -1;
        if (eFTid >= 0 && valuetid != eFTid)
        {
          valuetid = -1;
          eFTid = -1;
        }
        if (valuetid == -1)
        {
          state = ParserState::EOFF;
          eof = true;
          return false;
          // break;
        }
        else
        {
          eFTid = -1;
          if (valuetid == TID_TYPEDECL)
          {
            if (valuelen == 0)
            {
              checkversionmarker();
              if (readerr) return false;
            }
            else
            {
              loadannotations();
              if (readerr) return false;
            }
          }
        }
      };
      break;
      case ParserState::BeforeValue:
      {
        skip(valuelen);
        if (readerr) return false;
        state = ParserState::AfterValue;
      };
      break;

      case ParserState::AfterValue:
      {
        if (isinstruct)
        {
          state = ParserState::BeforeField;
        }
        else
        {
          state = ParserState::BeforeTID;
        }
      };
      break;
      default:
      {
        if (state != ParserState::EOFF) return false;
        eof = true;
      };
      break;
      }
      if (eof) break;
    }
    return true;
  }
  bool hasnext()
  {
    if (readerr) return false;
    while (needhasnext && !eof)
    {
      if (!hasnextraw()) return false;
      // std::cout << "Might have next" << std::endl;
      if (containerstack.size() == 0 && !valueisnull)
      {
        if (valuetid == TID_SYMBOL)
        {
          if (vtype == IonVtype::Integer && ival == SID_ION_1_0)
          {
            needhasnext = true;
          }
        }
        else
        {
          if (valuetid == TID_STRUCT)
          {
            for (size_t ii = 0; ii < annotations.size(); ii++)
            {
              if (annotations[ii] == SID_ION_SYMBOL_TABLE)
              {
                parsesymboltable();
                needhasnext = true;
              }
            }
          }
        }
      }
    }
    return !eof;
  }

  int next()
  {
    if (readerr) return -1;
    if (hasnext())
    {
      needhasnext = true;
      return valuetid;
    }
    return -1;
  }
  int readtypeid()
  {
    if (readerr) return -1;
    if (localremaining != -1)
    {
      if (localremaining < 1) return -1;
      localremaining -= 1;
    }
    if (stream_pos >= maxstrlen)
    {
      readerr = true;
      return -1;
    }
    uint8_t b = stream[stream_pos];
    stream_pos += 1;
    int result = (int)b;
    result = result >> 4;
    int ln = (int)b & 0xf;
    if (ln == LEN_IS_VAR_LEN)
    {
      ln = readvaruint();
      if (readerr) return -1;
    }
    else
    {
      if (ln == LEN_IS_NULL)
      {
        ln = 0;
        state = ParserState::AfterValue;
      }
      else if (result == TID_NULL)
      {
        readerr = true; // invalid stream
        return -1;
      }
      else if (result == TID_BOOLEAN)
      {
        if (ln > 1)
        {
          readerr = true; // invalid stream
          return -1;
        }
        valueistrue = (ln == 1);
      }
      else if (result == TID_STRUCT)
      {
        if (ln == 1)
        {
          ln = readvaruint();
        }
      }
    }
    valuelen = ln;
    // std::cout << "Rlen: " << ln << std::endl;
    return result;
  }
  void stepin()
  {

    if (readerr) return;
    // std::cout << "Valuetid: " << valuetid << std::endl;
    if (eof)
    {
      readerr = true;
      return;
    }
    if (valuetid != TID_STRUCT && valuetid != TID_LIST && valuetid != TID_SEXP)
    {
      readerr = true;
      return;
    }

    if (!((!valueisnull || state == ParserState::AfterValue) && (valueisnull || state == ParserState::BeforeValue)))
    {
      readerr = true;
      return;
    }
    int nextrem = localremaining;
    if (nextrem != -1)
    {
      nextrem -= valuelen;
      if (nextrem < 0)
      {
        readerr = true;
        return;
      }
    }
    push(parenttid, stream_pos + valuelen, nextrem);
    isinstruct = (valuetid == TID_STRUCT);
    if (isinstruct)
    {
      state = ParserState::BeforeField;
    }
    else
    {
      state = ParserState::BeforeTID;
    }
    localremaining = valuelen;
    parenttid = valuetid;
    clearvalue();
    needhasnext = true;
  }
  void stepout()
  {
    if (readerr) return;
    if (containerstack.size() == 0)
    {
      readerr = true;
      return;
    }
    // std::cout << "Stepping out " << std::endl;
    ContainerRec rec = containerstack.back();
    containerstack.pop_back();
    eof = false;
    parenttid = rec.tid;
    if (parenttid == (int)TID_STRUCT)
    {
      isinstruct = true;
      state = ParserState::BeforeField;
    }
    else
    {
      isinstruct = false;
      state = ParserState::BeforeTID;
    }
    needhasnext = true;
    clearvalue();
    int curpos = (int)stream_pos;
    // std::cout << "Curpos " << curpos << " nextpos " << rec.nextpos << std::endl;
    if (rec.nextpos > curpos)
    {
      skip(rec.nextpos - curpos);
    }
    else
    {
      if (rec.nextpos != curpos)
      {
        readerr = true;
        return;
      }
    }
    localremaining = rec.remaining;
  }
  long long readdecimal()
  {
    if (valuelen == 0)
    {
      return 0;
    }
    if (readerr) return 0;

    int rem = localremaining - valuelen;
    localremaining = valuelen;
    int exponent = readvarint();
    if (readerr) return 0;
    if (localremaining <= 0 || localremaining > 8)
    {
      readerr = true;
      return 0;
    }
    bool sign = false;
    uint8_t *b = read(localremaining);
    if (readerr) return 0;
    if ((b[0] & 0x80) != 0)
    {
      sign = true;
    }
    long long v = 0;
    for (int j = 0; j < localremaining; j++)
    {
      uint8_t bb = b[j];
      if (j == 0 && sign)
      {
        bb = bb & 0x7f;
      }
      v = (v >> 8) + bb;
    }
    long long res = (long long)v;
    for (int e = 0; e < exponent; e++) // this be dumb;
    {
      res *= e;
    }
    if (sign)
    {
      res = -res;
    }
    localremaining = rem;
    return res;
  }
  void parsesymboltable()
  {
    next();
    if (valuetid != TID_STRUCT)
    {
      readerr = true;
      return;
    }
    if (didimports) return;
    stepin();
    int fieldtype = next();
    // std::cout << "Fieldtype " << fieldtype << std::endl;
    while (fieldtype != -1)
    {
      if (!valueisnull)
      {
        if (valuefieldid != SID_IMPORTS)
        {
          readerr = true;
          return;
        }
        if (fieldtype == TID_LIST)
        {
          gatherimports();
        }
      }
      fieldtype = next();
      // std::cout << "Fieldtype " << fieldtype << std::endl;
    }
    stepout();
    didimports = true;
  }
  void gatherimports()
  {
    stepin();
    int t = next();
    while (t != -1)
    {
      if (!valueisnull && t == TID_STRUCT)
      {
        readimport();
      }
      t = next();
    }
    stepout();
  }
  void erval() { vtype = IonVtype::None; }
  void loadscalarvalue()
  {
    if (valuetid != TID_NULL && valuetid != TID_BOOLEAN && valuetid != TID_POSINT && valuetid != TID_NEGINT && valuetid != TID_FLOAT &&
        valuetid != TID_DECIMAL && valuetid != TID_SYMBOL && valuetid != TID_STRING && valuetid != TID_TIMESTAMP)
    {
      return;
    }
    // std::cout << "Load scalar val " << std::endl;
    if (valueisnull)
    {
      erval();
      return;
    }
    erval();
    switch (valuetid)
    {
    case TID_STRING:
    {
      char *buf = (char *)read(valuelen);
      if (readerr) return;
      assignIonValue(std::string(buf, valuelen));
    };
    break;
    case TID_POSINT:
    case TID_NEGINT:
    case TID_SYMBOL:
    {
      if (valuelen == 0)
      {
        assignIonValue((int)0);
      }
      else
      {
        if (valuelen > 4)
        {
          readerr = true;
          return;
        }
        int v = 0;
        for (int j = 0; j < valuelen; j++)
        {
          uint8_t *b = read();
          if (readerr) return;
          v = (v << 8) + b[0];
        }
        if (valuetid == TID_NEGINT)
        {
          v = -v;
        }
        assignIonValue(v);
      }
    };
    break;
    case TID_DECIMAL:
    {
      long long r = readdecimal();
      if (readerr) return;
      assignIonValue(r);
    };
    break;
    default:
      readerr = true;
    }
    state = ParserState::AfterValue;
  }

  void preparevalue()
  {
    if (vtype == IonVtype::None)
    {
      loadscalarvalue();
    }
  }
  IonCatalogItem findcatalogitem(const std::string &name)
  {
    for (auto it = catalog.begin(); it != catalog.end(); ++it)
    {
      if (it->name == name)
      {
        return *it;
      }
    }
    return IonCatalogItem("-", -1, std::vector<std::string>()); // also dumb
  }

  void readimport()
  {
    int version = -1;
    int maxid = -1;
    std::string name = "";
    stepin();
    int t = next();
    while (t != -1)
    {
      if (!valueisnull && valuefieldid != SID_UNKNOWN)
      {
        switch (valuefieldid)
        {
        case SID_NAME:
        {
          name = stringvalue();
        };
        break;
        case SID_VERSION:
        {
          version = intvalue();
        };
        break;
        case SID_MAX_ID:
        {
          maxid = intvalue();
        };
        break;
        default:
          break;
        }
      }
      t = next();
    }
    stepout();
    if (name == "" || name == SystemSymbols_ION)
    {
      return;
    }
    if (version < 1) version = 1;
    IonCatalogItem table = findcatalogitem(name);
    if (maxid < 0)
    {
      if (table.name == "-")
      {
        readerr = true;
        return;
      }
      if (version != table.version)
      {
        readerr = true;
        return;
      }
      maxid = (int)table.symnames.size();
    }
    if (table.name != "-")
    {
      symbols.import_(table.symnames, (size_t)maxid > table.symnames.size() ? table.symnames.size() : maxid);
      if (table.symnames.size() < (size_t)maxid)
      {
        symbols.importunknown(name + "-unknown", maxid - table.symnames.size());
      }
    }
    else
    {
      symbols.importunknown(name, maxid);
    }
  }
  int intvalue()
  {
    if (valuetid != TID_POSINT && valuetid != TID_NEGINT)
    {
      readerr = true;
      return 0;
    }
    preparevalue();
    if (readerr || vtype == IonVtype::None)
    {
      return 0;
    }
    return ival;
  }

  std::string stringvalue()
  {
    // std::cout << "Stringvalue" << std::endl;
    if (valuetid != TID_STRING)
    {
      readerr = true;
      return "";
    }
    preparevalue();
    if (readerr || vtype == IonVtype::None)
    {
      return "";
    }
    // std::cout << "Stringvalue out " << sval<<std::endl;
    return sval;
  }
  std::string symbolvalue()
  {
    if (valuetid != TID_SYMBOL)
    {
      readerr = true;
      return "";
    }
    preparevalue();
    if (readerr || vtype == IonVtype::None)
    {
      return "";
    }
    std::string result = symbols.findbyid(ival);
    if (result == "")
    {
      std::ostringstream s;
      s << "SYMBOL#" << (ival);
      result = s.str();
    }
    return result;
  }
  std::vector<uint8_t> lobvalue()
  {
    if (valuetid != TID_CLOB && valuetid != TID_BLOB)
    {
      readerr = true;
      return std::vector<uint8_t>();
    }
    if (valueisnull)
    {
      return std::vector<uint8_t>();
    }
    uint8_t *buf = read(valuelen);
    if (readerr)
    {
      return std::vector<uint8_t>();
    }
    state = ParserState::AfterValue;
    return std::vector<uint8_t>(&buf[0], &buf[valuelen]);
  }
  long long decimalvalue()
  {
    if (valuetid != TID_DECIMAL)
    {
      readerr = true;
      return 0;
    }
    preparevalue();
    if (readerr || vtype == IonVtype::None)
    {
      return 0;
    }
    return lval;
  }
  void loadannotations()
  {
    unsigned int ln = readvaruint();
    if (readerr) return;
    size_t maxpos = stream_pos + ln;
    // std::cout << "Annots " << ln<<std::endl;
    while (stream_pos < maxpos)
    {
      unsigned int nx = readvaruint();
      if (readerr) return;
      // std::cout << "Annotation " << nx << std::endl;
      annotations.push_back(nx);
    }
    valuetid = readtypeid();
  }
  void forceimport(const std::vector<std::string> &sym) { symbols.import_(sym, sym.size()); }
  std::string getfieldname()
  {
    if (valuefieldid == SID_UNKNOWN) return "";
    return symbols.findbyid(valuefieldid);
  }
  void checkversionmarker()
  {
    uint8_t *rd = read(sizeof(VERSION_MARKER));

    if (readerr) return;
    for (int i = 0; i < sizeof(VERSION_MARKER); i++)
    {
      if (rd[i] != VERSION_MARKER[i])
      {
        readerr = true;
        return;
      }
    }
    valuelen = true;
    valuetid = TID_SYMBOL;
    assignIonValue(SID_ION_1_0);
    valueisnull = false;
    valuefieldid = SID_UNKNOWN;
    state = ParserState::AfterValue;
  }
  SymbolToken getfieldnamesymbol() { return SymbolToken(getfieldname(), valuefieldid); }
  std::string gettypename()
  {
    if (annotations.size() == 0) return "";
    return symbols.findbyid(annotations[0]);
  }
  int getAnnotType()
  {
    if (annotations.size() == 0) return -1;
    return annotations[0];
  }
};

std::vector<std::string> SYM_NAMES()
{
  std::vector<std::string> SYM_NAMESr = {"com.amazon.drm.Envelope@1.0",
                                         "com.amazon.drm.EnvelopeMetadata@1.0",
                                         "size",
                                         "page_size",
                                         "encryption_key",
                                         "encryption_transformation",
                                         "encryption_voucher",
                                         "signing_key",
                                         "signing_algorithm",
                                         "signing_voucher",
                                         "com.amazon.drm.EncryptedPage@1.0",
                                         "cipher_text",
                                         "cipher_iv",
                                         "com.amazon.drm.Signature@1.0",
                                         "data",
                                         "com.amazon.drm.EnvelopeIndexTable@1.0",
                                         "length",
                                         "offset",
                                         "algorithm",
                                         "encoded",
                                         "encryption_algorithm",
                                         "hashing_algorithm",
                                         "expires",
                                         "format",
                                         "id",
                                         "lock_parameters",
                                         "strategy",
                                         "com.amazon.drm.Key@1.0",
                                         "com.amazon.drm.KeySet@1.0",
                                         "com.amazon.drm.PIDv3@1.0",
                                         "com.amazon.drm.PlainTextPage@1.0",
                                         "com.amazon.drm.PlainText@1.0",
                                         "com.amazon.drm.PrivateKey@1.0",
                                         "com.amazon.drm.PublicKey@1.0",
                                         "com.amazon.drm.SecretKey@1.0",
                                         "com.amazon.drm.Voucher@1.0",
                                         "public_key",
                                         "private_key",
                                         "com.amazon.drm.KeyPair@1.0",
                                         "com.amazon.drm.ProtectedData@1.0",
                                         "doctype",
                                         "com.amazon.drm.EnvelopeIndexTableOffset@1.0",
                                         "enddoc",
                                         "license_type",
                                         "license",
                                         "watermark",
                                         "key",
                                         "value",
                                         "com.amazon.drm.License@1.0",
                                         "category",
                                         "metadata",
                                         "categorized_metadata",
                                         "com.amazon.drm.CategorizedMetadata@1.0",
                                         "com.amazon.drm.VoucherEnvelope@1.0",
                                         "mac",
                                         "voucher",
                                         "com.amazon.drm.ProtectedData@2.0",
                                         "com.amazon.drm.Envelope@2.0",
                                         "com.amazon.drm.EnvelopeMetadata@2.0",
                                         "com.amazon.drm.EncryptedPage@2.0",
                                         "com.amazon.drm.PlainText@2.0",
                                         "compression_algorithm",
                                         "com.amazon.drm.Compressed@1.0",
                                         "page_index_table"};
  // can not be bothered...
  for (int i = 1; i < 200; i++)
  {
    std::ostringstream s;
    s << "com.amazon.drm.VoucherEnvelope@" << (i);
    SYM_NAMESr.push_back(s.str());
  }
  return SYM_NAMESr;
}
void addprottable(BinaryIonParser *ion)
{
  if (!ion) return;
  ion->addtocatalog("ProtectedData", 1, SYM_NAMES());
}

int finIndexIn(const std::vector<std::string> &p, const std::string &val)
{
  for (size_t i = 0; i < p.size(); i++)
  {
    if (p[i] == val) return i;
  }
  return -1;
}

//--------------------------------------------------end ION
class BasicDecryptor
{
public:
  virtual bool decrypt(std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &iv, std::vector<uint8_t> &out) = 0;
};
class AesDecryptor : public BasicDecryptor
{
public:
  std::vector<uint8_t> key;
  AesDecryptor(const std::vector<uint8_t> &k) : key(k) {}
  virtual bool decrypt(std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &iv, std::vector<uint8_t> &out)
  {
    if (iv.size() != 16)
    {
      printf("Unsupported IV size %ld\n", iv.size());
      out.resize(0);
      return false;
    }
    out.resize(ciphertext.size());
    unsigned long padded_size = 0;
    plusaes::Error err = plusaes::decrypt_cbc(&ciphertext[0], ciphertext.size(), &key[0], key.size(), (unsigned char(*)[16]) & iv[0], &out[0],
                                              out.size(), &padded_size);
    if (err != plusaes::kErrorOk) return false;
    // printf("Padding %ld",padded_size);
    out.resize(out.size() - padded_size);
    return true;
  }
};

std::vector<uint8_t> HexToBytes(const std::string &hex)
{
  std::vector<uint8_t> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2)
  {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}
std::vector<char> HexToBytesC(const std::string& hex) {
    std::vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}


std::vector<uint8_t> drmionHeader = HexToBytes("ea44524d494f4eee");
std::vector<uint8_t> fake = HexToBytes("e00100eaee9e8183de9a86be97de95848d50726f74656374656444617461852101882180ee03c381d3de03bea4eec981a7dec5a3be9a8e8e4143434f554e545f53454352455489434c49454e545f49449e834145538f8e944145532f4342432f504b43533550616464696e679f8a486d6163534841323536c0aea0ccbc90f3ac6e4a1a1f0352e9870a2801c287d651f942337aef0a21dfa95ae49cc1ae02cbe00100eaee9e8183de9a86be97de95848d50726f74656374656444617461852101882180ee02a481adde029fa28eb9616d7a6e312e64726d2d766f75636865722e76312e30303030303030302d303030302d303030302d303030302d30303030303030303030303096ae903992d248da68e4d3371739cf3711623295a87465737464617461f8aec0a2eddd1bd68d5fc98e60c2c915fe9b4bec38e23d98d41f10068ec3afe38002173facf2260318cdb8726b1b3a274ec529d000724d29a04bfc399848041eda5711b6eea781badea3b5885075726368617365b78e966174763a6b696e3a323a6447567a644752686447453dbdeed681bebed2ded0bb8e93636c69656e745f7265737472696374696f6e73bcbeb7de95b88d436c697070696e674c696d6974b98431353030de9eb88e9454657874546f53706565636844697361626c6564b98566616c7365");
bool write_vector_to_file(const fs::path& target_path, const std::vector<uint8_t>& data) 
{
    if (target_path.has_parent_path() && !fs::exists(target_path.parent_path())) {
        fs::create_directories(target_path.parent_path());
    }

    std::ofstream file(target_path, std::ios::out | std::ios::binary);

    if (!file) {
        std::cerr << "Error: Failed to open path for writing: " << target_path << "\n";
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());

    return file.good();
}


bool processPage(std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &iv, BasicDecryptor *decr, bool decompress, bool decrypt,
                 std::vector<uint8_t> &out)
{

  std::vector<uint8_t> msg;
  if (decrypt)
  {
    if (!decr->decrypt(ciphertext, iv, msg)) return false;
  }
  else
  {
    msg = ciphertext;
  }
  // printf("Got message %ld\n",msg.size());
  if (!decompress)
  {
    out = msg;
    return true;
  }
  if (msg[0] != 0)
  {
    printf("Unsupported compression type %d\n", (int)msg[0]);
    return false;
  }

  plz::PocketLzma p;
  std::vector<uint8_t> decompressed;
  // std::cout << "Lzma hex " << hexStr(&msg[1], msg.size()-1) << std::endl;
  plz::StatusCode status = p.decompress(&msg[1], msg.size() - 1, decompressed);
  // printf("Got decomp %ld\n",decompressed.size());
  if (status == plz::StatusCode::Ok)
  {
    out = decompressed;
    return true;
  }
  printf("LZMA decompression failed!\n"); // maybe throw?
  return false;
}
bool processDRMION(char *buf, size_t size, BasicDecryptor *decr, std::vector<uint8_t> &out, bool &has_encryption, std::string& keyname)
{
  BinaryIonParser bp((unsigned char *)buf, size, -1);
  addprottable(&bp);
  has_encryption = false;
  if (!bp.hasnext())
  {
    printf("Invalid DRMION? \n");
    return false;
  }
  out.clear();
  int nxt = bp.next();
  if (nxt != TID_SYMBOL)
  {
    printf("Symbol not detected in DRMION \n");
    return false;
  }
  if (bp.next() != TID_LIST)
  {
    printf("List not detected in drmion\n");
    return false;
  }
  while (true)
  {
    if (bp.gettypename() == "enddoc") break;

    bp.stepin();

    while (bp.hasnext())
    {
      bp.next();
      std::string nm = bp.gettypename();
      // printf("Typename %s\n",nm.c_str());
      if (nm == "com.amazon.drm.EnvelopeMetadata@1.0" || nm == "com.amazon.drm.EnvelopeMetadata@2.0")
      {
         //printf("Typename %s\n",nm.c_str());
        bp.stepin();
        while (bp.hasnext())
        {
          bp.next();
          std::string tn = bp.getfieldname();
          //printf("Inner fieldname %s\n",tn.c_str());
          if (tn == "encryption_key") keyname = bp.stringvalue();
        
        }
        bp.stepout();
      }
      if (nm == "com.amazon.drm.EncryptedPage@1.0" || nm == "com.amazon.drm.EncryptedPage@2.0")
      {
        has_encryption = true;
        bool decompress = false;
        bool decrypt = true;
        std::vector<uint8_t> ct;
        std::vector<uint8_t> civ;
        bp.stepin();
        while (bp.hasnext())
        {
          bp.next();
          if (bp.gettypename() == "com.amazon.drm.Compressed@1.0") decompress = true;
          if (bp.getfieldname() == "cipher_text") ct = bp.lobvalue();
          if (bp.getfieldname() == "cipher_iv") civ = bp.lobvalue();
        }
        if (!ct.empty() && !civ.empty())
        {
          // std::cout <<"Got page " <<std::endl;
          std::vector<uint8_t> page;
          if (!processPage(ct, civ, decr, decompress, decrypt, page)) return false;
          // printf("Got page of size %ld\n", page.size());

          out.insert(out.end(), page.begin(), page.end());
        }
        bp.stepout();
      }
      else
      {
        if (nm == "com.amazon.drm.PlainText@1.0" || nm == "com.amazon.drm.PlainText@2.0")
        {
          bool decrypt = false;
          bool decompress = false;
          std::vector<uint8_t> plaintext;
          bp.stepin();
          while (bp.hasnext())
          {
            bp.next();
            if (bp.gettypename() == "com.amazon.drm.Compressed@1.0") decompress = true;
            if (bp.getfieldname() == "data") plaintext = bp.lobvalue();
          }
          if (!plaintext.empty())
          {
            std::vector<uint8_t> page;
            if (!processPage(plaintext, plaintext, decr, decompress, decrypt, page)) return false;
            out.insert(out.end(), page.begin(), page.end());
          }
          bp.stepout();
        }
      }
    }
    bp.stepout();
    if (!bp.hasnext()) break;
    bp.next();
  }
  return true;
}
bool read_file_to_vector(const std::string &filename, std::vector<char> &buffer)
{
  std::ifstream file(filename, std::ios::binary | std::ios::ate);

  if (!file.is_open())
  {  std::cerr << "Error: " << strerror(errno) << " (" << filename << ")" << std::endl;

    return false;
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  std::cout << "File size " << size << std::endl;
  buffer.resize(size);
  std::cout << "Buffer resized " << buffer.size() << std::endl;
  if (file.read(reinterpret_cast<char *>(buffer.data()), size))
  {
    return true;
  }

  return false;
}


std::vector<char> read_proc_file(const std::string& path) {
    // Open without std::ios::ate
    std::ifstream file(path, std::ios::binary);
    
    if (!file.is_open()) return {};

    // Iterators will read until EOF is reached
    return std::vector<char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

std::string read_file_to_string(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    
    if (!file.is_open()) return {};
    return std::string(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

bool get_drmion(const fs::path &path, std::vector<char> &buf)
{
  if (!fs::is_regular_file(path)) return false;
  if (!read_file_to_vector(path.string(), buf))
  {
    printf("Could not read file? \n");
    return false;
  }
  // std::cout <<"Got file " <<std::endl;
  if (buf.size() > drmionHeader.size() && memcmp(&drmionHeader[0], buf.data(), drmionHeader.size()) == 0)
  {
    return true;
  }
  return false;
}
std::vector<std::vector<uint8_t>> test_drmions_for_keys(const std::vector<fs::path> &paths, const std::vector<std::vector<uint8_t>> &keys,std::string& keyname)
{
  std::vector<std::vector<uint8_t>> ret = keys;
  bool found_encryption = false;
  if (keys.size() == 0)
  {
    printf("No key candidates!\n");
    return ret;
  }
  for (const auto &file : paths)
  {
    std::vector<char> drmion;
    if (!get_drmion(file, drmion))
    {
      continue;
    }
    bool has_encryption = false;
    std::vector<uint8_t> outme;
    std::cout << "Got drmion " << std::endl;
    for (auto key = ret.begin(); key != ret.end();)
    {
      AesDecryptor decr(*key);
      // std::cout <<"Got decr " << hexStr(&(*key)[0],16) <<std::endl;
      if (processDRMION(&drmion[8], drmion.size() - 16, &decr, outme, has_encryption,keyname))
      {
        ++key;
      }
      else
      {
        key = ret.erase(key);
      }
      if (has_encryption)
      {
        found_encryption = true;
      }
      else
      {
        break; // no point in continuing
      }
    }
    if (ret.size() <= 1) break; // only one candidate left or none worked
  }
  if (!found_encryption)
  {
    printf("No encryption in these \n");
    ret.resize(1);
  }
  return ret;
}
int processFile(const char *outputFile, const std::string &fname, const std::string &archivedName, BasicDecryptor *decr)
{

  size_t bl = 0;
  std::vector<char> buf;
  if (!read_file_to_vector(fname, buf))
  {
    printf("Could not read file? \n");
    return 1;
  }
  bl = buf.size();
  printf("Read file of %lu bytes\n", buf.size());
  if (bl == 0)
  {
    return 0;
  }
   std::string discard;
  if (bl > drmionHeader.size() && memcmp(&drmionHeader[0], buf.data(), drmionHeader.size()) == 0)
  {
    std::vector<uint8_t> outme;
    printf("Decrypting DRMION... \n");
    bool has_enc;
    if (processDRMION(&buf[8], bl - 16, decr, outme, has_enc,discard))
    {
      mz_bool status =
          mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), outme.data(), outme.size(), NULL, 0, MZ_BEST_COMPRESSION);
      if (!status)
      {
        printf("mz_zip_add_mem_to_archive_file_in_place of DRMION file failed!\n");
        return EXIT_FAILURE;
      }
      printf("DRMION decrypted and saved.\n");
    }
    else
    {
      printf("Could not decrypt DRMION? \n");
      return 2;
    }
  }
  else
  {
    mz_bool status = mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), buf.data(), bl, NULL, 0, MZ_BEST_COMPRESSION);
    if (!status)
    {
      printf("mz_zip_add_mem_to_archive_file_in_place of non-DRM file  failed!\n");
      return EXIT_FAILURE;
    }
  }

  return 0;
}

void kfx_scan(const fs::path& assets,std::vector<fs::path>& acc)
{
  for (const auto &entry : fs::directory_iterator(assets))
  {
    if (entry.is_directory())
    {
      kfx_scan(entry.path(),acc);
    }
    if(fs::is_regular_file(entry.path())&&entry.path().extension()==".kfx")
    {
      acc.push_back(entry.path());
    }
  }
}



bool process_assets(const std::string &bookid,const fs::path& kfx_path, std::map<std::string, std::vector<fs::path>>& att)
{
  fs::path metadir=kfx_path.parent_path()/(kfx_path.stem().string()+".sdr")/"assets";
  if (!fs::is_directory(metadir)) return false;
  std::vector<fs::path> vouchers;
  fs::path vouch=metadir/"voucher";
  if(fs::is_regular_file(vouch))
  {
    vouchers.push_back(vouch);
  }
  att["vouchers"]=vouchers;
  std::vector<fs::path> bf;
  bf.push_back(kfx_path);
  att["bookFiles"] = bf;
  std::vector<fs::path> resources;
  resources.push_back(kfx_path);
  kfx_scan(metadir,resources);
  att["resources"]=resources;
  return true;
}

void mobi_scan(const fs::path& assets,std::vector<fs::path>& acc)
{
  //std::cout << "MOBI scanning " <<assets <<std::endl;
  for (const auto &entry : fs::directory_iterator(assets))
  {
    if (entry.is_directory())
    {
      mobi_scan(entry.path(),acc);
    }
    std::string ex=entry.path().extension();
    if(fs::is_regular_file(entry.path())&&(ex==".mobi"||ex==".azw3"||ex==".azw4"))
    {
      acc.push_back(entry.path());
      std::cout << "Adding " << entry.path().filename() << " as MOBI book candidate" << std::endl;
    }
  }
}


void scan_folder_for_book_candidates(const fs::path &collection, std::vector<fs::path> &book_folders)
{
  for (const auto &entry : fs::directory_iterator(collection))
  {
  
      if(fs::is_regular_file(entry.path())&&entry.path().extension()==".kfx")
      {
        fs::path metadir=collection/(entry.path().stem().string()+".sdr");
         if (fs::is_directory(metadir))
         {
           std::cout << "Adding " << entry.path().filename() << " as book candidate" << std::endl;
           book_folders.push_back(entry.path());
         }
      }
      if(fs::is_directory(entry.path())&&entry.path().extension()!=".sdr")
      {
        scan_folder_for_book_candidates(entry.path(),book_folders);
      }
    
    
  }
}



typedef void *(*mlc)(size_t);
mlc real_malloc;
typedef void (*fr)(void *);
fr real_free;
std::map<void *, size_t> allocations;
std::set<std::vector<uint8_t>> key_candidates;
void *my_malloc(size_t size)
{
  printf("Intercepted malloc call for %zu bytes\n", size);
  void *pt = real_malloc(size);
  if (size == 16)
  {
    allocations[pt] = 16;
  }
  return pt;
}
void my_free(void *pt)
{
  if (pt != nullptr)
  {
    auto fnd = allocations.find(pt);
    if (fnd != allocations.end())
    {
      std::cout << hexStr((uint8_t *)pt, 16) << std::endl;
      //key_candidates.insert(std::vector<uint8_t>((uint8_t *)pt, (uint8_t *)pt + 16));

      allocations.erase(fnd);
    }
  }
  free(pt);
}
typedef void *(*dlo)(const char *filename, int flag);
dlo real_dlopen=nullptr;
void *dlopen_new(const char *filename, int flag)
{
  printf("Dlopen: %s \n",filename);
  return real_dlopen(filename,flag);
}
typedef std::string * (*crstr)(std::string *me, std::string * other);
crstr real_mcreate;
void *mcreate_new(std::string *me, std::string * other)
{
  printf("mcreate_new: %s \n",other->c_str());
  return real_mcreate(me,other);
}
void delete_str(std::string* st)
{
 std::cout <<"Deleting string "<<std::endl;
 std::cout<<*st<<std::endl; 
}
//int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,EVP_CIPHER *cipher,ENGINE *impl,uchar *key,uchar *iv)
typedef int (*aesDecrypt)(void*,void*,void*,char*key,char*iv);
typedef int (*keylen)(const void *cipher);
typedef int (*decryptUpdate)(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
typedef int (*decryptFinal_ex)(void *ctx, unsigned char *out, int *outl);

aesDecrypt aesDecrypt_real;
keylen key_len_real;
decryptUpdate decryptUpdate_real;
decryptFinal_ex decryptFinal_real;
bool allhex(uint8_t* p, size_t ln)
{
    bool brk = false;
    for (int i = 0; i < ln; i++)
    {
        if (!isxdigit(p[i]) || p[i] == 0)
        {
            brk = true;
            break;
        }
    }
    return !brk;
}



int aesDecrypt_new(void*ctx,void*cipher,void*impl,char*key,char*iv)
{
   printf("AES decrypt called with key len %d\n",key_len_real(cipher));
     std::cout <<hexStr((const unsigned char*)key,key_len_real(cipher))<<std::endl;
  if(key_len_real(cipher)==16)
  {
  printf("AES decrypt called %p\n",aesDecrypt_real);

  //std::vector<char> vec(data, data + length);
  key_candidates.insert(std::vector<uint8_t>((uint8_t *)key, (uint8_t *)key + 16));
  }
  return aesDecrypt_real(ctx,cipher,impl,key,iv);
}
unsigned char *seccandidate=NULL;
std::set<std::string> secret_candidates;
int EVP_DecryptUpdate_new(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
  printf("Calling decryptUpdate with %d input to %p \n",inl,out);
  int ret= decryptUpdate_real(ctx,out,outl,in,inl);
  printf("Called decryptUpdate with res %d outl %d \n",ret,*outl);
  if(inl==48&&ret>0)
  {
    seccandidate=out;
  }

  return ret;
  
}
int EVP_DecryptFinal_ex_new(void *ctx, unsigned char *out, int *outl)
{
  printf("Calling EVP_DecryptFinal_ex to %p \n",out);
  int ret= decryptFinal_real(ctx,out,outl);
  if(seccandidate!=NULL)
  {
    if(allhex(seccandidate, 40))
    {
      std::string cand = std::string((char*)seccandidate, 40);
      secret_candidates.insert(cand);
    }
  }
  return ret;

}


void install_hook(void *lib_symbol)
{
  real_malloc = (mlc)dlsym(RTLD_NEXT, "malloc");
  real_free = (fr)dlsym(RTLD_NEXT, "free");
  real_dlopen = (dlo)dlsym(RTLD_NEXT, "dlopen");
  real_mcreate = (crstr)dlsym(RTLD_NEXT, "_ZNSsC1ERKSs");
  void * chandle=dlopen("/usr/lib/libcrypto.so",RTLD_NOW);
  printf("Openssl handle: %p\n",chandle);
  aesDecrypt_real=(aesDecrypt)dlsym(chandle,"EVP_DecryptInit_ex");
  decryptUpdate_real=(decryptUpdate)dlsym(chandle,"EVP_DecryptUpdate");
  decryptFinal_real=(decryptFinal_ex)dlsym(chandle,"EVP_DecryptFinal_ex");
  
  key_len_real=(keylen)dlsym(chandle,"EVP_CIPHER_key_length");
  if(key_len_real==nullptr)
  {
    key_len_real=(keylen)dlsym(chandle,"EVP_CIPHER_get_key_length");
  }
  if(key_len_real==nullptr)
  {
    printf("Could not find key length routine, unsupported OpenSSL? \n");
    printf("%p \n",aesDecrypt_real);
    exit(2);
  }
  printf("aesDecrypt %p decryptUpdate %p decryptFinal %p key_len %p \n",aesDecrypt_real,decryptUpdate_real,decryptFinal_real,key_len_real);
  plthook_t *plthook;

  if (plthook_open_by_address(&plthook, lib_symbol) != 0)
  {
    printf("could not create plthook\n");
    return;
  }

  //plthook_replace(plthook, "malloc", (void *)my_malloc, NULL);
  //plthook_replace(plthook, "free", (void *)my_free, NULL);
  //plthook_replace(plthook, "dlopen", (void *)dlopen_new, NULL);
  //plthook_replace(plthook, "_ZNSsC1ERKSs", (void *)mcreate_new, NULL);
 // plthook_replace(plthook, "_ZNSsD1Ev", (void *)delete_str, NULL);
  plthook_replace(plthook, "EVP_DecryptInit_ex", (void *)aesDecrypt_new, NULL);
  plthook_replace(plthook, "EVP_DecryptUpdate", (void *)EVP_DecryptUpdate_new, NULL);
  plthook_replace(plthook, "EVP_DecryptFinal_ex", (void *)EVP_DecryptFinal_ex_new, NULL);
  plthook_close(plthook);
}

void print_stacktrace() {
    void* array[10];
    size_t size = backtrace(array, 10);
    std::cerr << "--- Exception thrown: Backtrace ---" << std::endl;
    backtrace_symbols_fd(array, size, 2); // 2 is stderr
    exit(1);
}

std::vector<std::string> split_secrets(const std::string& secrfile)
{
    std::stringstream ss(secrfile);
    std::string item;
    std::vector<std::string> result;

    while (std::getline(ss, item, ',')) {
        result.push_back(item);
    }

    return result;
}
// length over 36 will get mid-clipped by first 16 and last 17 symbols 
void updatemenufile(const std::vector<fs::path>&books,bool truncate)
{
  std::string expected_menu="/mnt/us/extensions/kfxdedrm/menu.json";
   std::ifstream file(expected_menu);
    if (!file.is_open())
    {
      throw std::runtime_error("Could not open file /mnt/us/extensions/kfxdedrm/menu.json for reading");
    }
    printf("Trying to update menu with %zu books \n",books.size());
    json data = json::parse(file);
    json alist=json::array();
    alist.push_back({{"name","Scan documents folder"},{"action", "bin/run_cmd.sh"},{"params","scan"},{"priority",1}});
    alist.push_back({{"name","Scan documents folder (truncate names)"},{"action", "bin/run_cmd.sh"},{"params","scantruncate"},{"priority",2}});
    int p=3;
    for(const auto& pth:books)
    {
      std::string bname=pth.stem();
      if (truncate&&bname.length()>40)
      {
        std::string front=bname.substr(0,16);
        std::string back=bname.substr(bname.length()-17);
        bname=front+"..."+back;
        std::replace(bname.begin(), bname.end(), ' ', '_');
      }
      std::string fpath=pth.string();
      alist.push_back({{"name",bname},{"action", "bin/run_cmd.sh"},{"params",std::string("dedrm \"")+fpath+"\""},{"priority",p}});
      p++;
    }
    if (data.contains("items") && data["items"].is_array()) 
   {
     for(auto& sub:data["items"])
     {
       if (sub.contains("items") && sub["items"].is_array()) 
   {
    for (auto& itm :sub["items"])
    {
      if (itm.contains("name")&&itm["name"].get<std::string>()=="Books")
      {
        printf("Found books \n");
        itm["items"]=alist;
        break;
      }
    }
   }
     }
   }
    file.close();
    std::ofstream outfile(expected_menu);
    outfile << data.dump(2); 
}

///MOBI stuff  

template<typename T>
size_t clen(T finalArg) 
{
    return finalArg.size();
}

template<typename T, typename... Args>
size_t clen(T first, Args... args) 
{
    return first.size() + clen(args...);
}


template<typename T>
void mcpy(std::vector<char>& into,size_t offset,T finalArg)
{
    memcpy(&into[offset], finalArg.data(),finalArg.size());
}

template<typename T, typename... Args>
void mcpy(std::vector<char>& into, size_t offset, T first, Args... args)
{
    memcpy(&into[offset], first.data(), first.size());
    mcpy(into, offset + first.size(), args...);
}

template<typename T>
std::vector<char> ccat(T finalArg)
{
    std::vector<char> ret(finalArg.begin(), finalArg.end());
    return ret;
}

template<typename T, typename... Args>
std::vector<char> ccat(T first, Args... args)
{   
    std::vector<char> sm(clen(first, args...));
    mcpy(sm, 0, first, args...);
    return sm;
}
std::vector<char> ReadFileToVector(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cout<<"Could not open" << strerror(errno) << std::endl;
        return std::vector<char>();
    }
    return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}
std::vector<char> ReadFileToVector(const fs::path& filePath) 
{

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Could not open" << strerror(errno) << std::endl;
        return std::vector<char>();
    }
    return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

}

class CRC32 {
private:
    uint32_t table[256];

public:
    CRC32() {
        uint32_t polynomial = 0xEDB88320;
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (uint32_t j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ polynomial;
                }
                else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
    }

    uint32_t Calculate(const uint8_t* data, size_t length) {
        uint32_t crc = 0;// 0xFFFFFFFF; // Initial value
        for (size_t i = 0; i < length; ++i) {
            uint8_t index = (crc ^ data[i]) & 0xFF;
            crc = (crc >> 8) ^ table[index];
        }
        return crc;// ^ 0xFFFFFFFF; // Final XOR
    }
};



std::string charMap1 = "n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M";
std::string charMap3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string charMap4 = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";

std::string encodeToMap(const std::vector<char>& data,const std::string& smap)
{
    std::ostringstream s;
    size_t l = smap.size();
    for (auto val : data)
    {
        int Q = (val ^ 0x80) / l;
        int R = (val) % l;
        s << smap[Q] << smap[R];
    }
    return s.str();
}
 std::vector<char> CalculateMD5Vector(const std::vector<char>& in)
 {
    std::vector<char> ret;
    ret.resize(MD5_SIZE);
    md5_context ctx;
    md5_init(&ctx);
    {
        md5_update(&ctx, &in[0], in.size());
    }
    md5_finalize(&ctx,(unsigned char *) &ret[0]);
   return ret;
 }


std::string encodeHashToMap(const std::vector<char>& data, const std::string& smap)
{
    return encodeToMap(CalculateMD5Vector(data), smap);
}

char getTwoBitsFromBitField(const std::vector<char>& bitField, int offset)
{
    int byteNumber = offset / 4;
    int bitPosition = 6 - 2 * (offset % 4);
    return bitField[byteNumber] >> bitPosition & 3;
}

char getSixBitsFromBitField(const std::vector<char>& bitField, int offset)
{
    offset *= 3;
    char value = value = (getTwoBitsFromBitField(bitField, offset) << 4) + (getTwoBitsFromBitField(bitField, offset + 1) << 2) + getTwoBitsFromBitField(bitField, offset + 2);
    return value;
}

std::string encodePID(const std::vector<char>& hash)
{
    std::ostringstream s;
    for (int pos = 0; pos < 8; pos++)
    {
        s << charMap3[getSixBitsFromBitField(hash, pos)];
    }
    return s.str();
}
 std::vector<char> CalculateSha1Vector(const std::vector<char>& in)
 {
    return sha1_from_scratch(in);
 }



std::vector<uint32_t> generatePidEncryptionTable()
{
    std::vector<uint32_t> ret;
    ret.reserve(0x100);
    for (uint32_t counter1 = 0; counter1 < 0x100; counter1++)
    {
        uint32_t value = counter1;
        for (uint32_t counter2 = 0; counter2 < 8; counter2++)
        {
            if ((value & 1) == 0)
            {
                value >>= 1;
            }
            else
            {
                value >>= 1;
                value = value ^ 0xEDB88320;
            }
        }
        ret.push_back(value);

    }
    return ret;
}

uint32_t generatePidSeed(const std::vector<uint32_t>& table,const std::string& dsn)
{
    uint32_t value = 0;
    for (int i = 0; i < 4; i++)
    {
        int index = (dsn[i] ^ value) & 0xff;
        value = (value >> 8) ^ table[index];
    }
    return value;
}

std::string generateDevicePID(const std::vector<uint32_t>& table, const std::string& dsn,int nbRoll)
{
    uint32_t seed = generatePidSeed(table, dsn);
    std::ostringstream s;
    std::vector<unsigned int> pid = {(seed>>24)&0xff,(seed >> 16) & 0xff, (seed >> 8) & 0xff ,(seed) & 0xff,(seed >> 24) & 0xff,(seed >> 16) & 0xff, (seed >> 8) & 0xff ,(seed) & 0xff };
    int index = 0;
    for (int cnt = 0; cnt < nbRoll; cnt++)
    {
        pid[index] = pid[index] ^ dsn[cnt];
        index = (index + 1) % 8;
    }
    for (int cnt = 0; cnt < 8; cnt++)
    {
        index = ((((pid[cnt] >> 5) & 3) ^ pid[cnt]) & 0x1f) + (pid[cnt] >> 7);
        s << charMap4[index];
    }
    return s.str();
}

std::string checksumPID(const std::string& pid)
{
    CRC32 crcCalculator;
    uint32_t crc = crcCalculator.Calculate((const uint8_t*)(pid.data()),pid.length());
    crc = crc ^ (crc >> 16);
    std::ostringstream s;
    s << pid;
    int l = charMap4.size();
    for (int a = 0; a <= 1; a++)
    {
        int b = crc & 0xff;
        int pos = (b / l) ^ (b % l);
        s << charMap4[pos % l];
        crc >>= 8;
    }
    return s.str();
}


std::vector<std::string> getK4Pids(const std::vector<char>& rec209, const std::vector<char>& token,const std::string& dsn, const std::vector<std::string>& extraKindleTokens)
{
    std::vector<std::string> ret;
    if (rec209.size() == 0)
    {
        for (auto accountToken : extraKindleTokens)
        {
            ret.push_back(dsn+ accountToken);
        }
        return ret;
    }
    std::vector<uint32_t> table = generatePidEncryptionTable();
    std::string devicePID = checksumPID(generateDevicePID(table,dsn,4));
    std::cout << "Device PID " <<devicePID <<std::endl;
    ret.push_back(devicePID);
    std::vector<char> sm;
    std::vector<char> pidHash;
    std::string bookPID;
    for (auto accountToken : extraKindleTokens)
    {
        sm = ccat(dsn, accountToken, rec209,token);
        pidHash = CalculateSha1Vector(sm);
        //std::string sm DSN + accToken + rec209 + token;
        bookPID=  checksumPID(encodePID(pidHash));
        std::cout << "Book PID " <<bookPID <<std::endl;
        ret.push_back(bookPID);
        sm = ccat( accountToken, rec209, token);
        pidHash = CalculateSha1Vector(sm);
        bookPID = checksumPID(encodePID(pidHash));
        std::cout << "Book PID " <<bookPID <<std::endl;
        ret.push_back(bookPID);
    }
    sm = ccat(dsn,  rec209, token);
    pidHash = CalculateSha1Vector(sm);
    bookPID = checksumPID(encodePID(pidHash));
    std::cout << "Book PID " <<bookPID <<std::endl;
    ret.push_back(bookPID);
    return ret;
}


class DrmException : public std::runtime_error
{
public:
    explicit DrmException(const std::string& message) : std::runtime_error(message) {}
};
//mz_zip_add_mem_to_archive_file_in_place(outputFile, archivedName.c_str(), outme.data(), outme.size(), NULL, 0, MZ_BEST_COMPRESSION)
struct BookInterface 
{
    virtual ~BookInterface() = default;
    virtual std::string getBookType() { return "UNK"; }
    virtual std::pair<std::vector<char>, std::vector<char>> getPIDMetaInfo() 
    { 
        return { std::vector<char>(), std::vector<char> ()};
    }
    virtual void processBook(const std::vector<std::string>& pids) {}
    virtual void cleanup() {}
    virtual std::string  getBookExtension() { return ".unk"; }
   // virtual void writeFile(const fs::path& fl) {};
  
};

void writeFileBasic(const fs::path& filename, const std::vector<char>& data)
{
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (!file)
    {
        std::cout << " Could not open file " << filename << " For writing " << strerror(errno) << std::endl;
        return;
    }
    //  std::cout << hexStr((uint8_t*) & data[0], 16) << std::endl;
    file.write(data.data(), data.size());
}

uint16_t unpack_H(const std::vector<char>& buffer, size_t offset = 0) 
{

    uint16_t b1 = buffer[offset];
    uint16_t b2 = (UCHAR)buffer[offset+1];
    return (b1<<8)|b2;
}

uint16_t unpack_H(const char* buffer, size_t offset = 0)
{
    return (static_cast<uint16_t>((UCHAR)buffer[offset]) << 8) |
        (static_cast<uint16_t>((UCHAR)buffer[offset + 1]));
}

size_t getSizeOfTrailingDataEntry(const char *ptr, size_t size)
{
    size_t bitpos = 0;
    size_t result = 0;
    if (size <= 0)
    {
        return result;
    }
    while (true)
    {
        UCHAR v = (UCHAR)ptr[size-1];
        result |= (v & 0x7F) << bitpos;
        bitpos += 7;
        size -= 1;
        if ((v & 0x80) != 0 || (bitpos >= 28) || (size == 0))
        {
            return result;
        }
    }
    return 0;
}

size_t getSizeOfTrailingDataEntries(const char* ptr, size_t size,uint32_t flags)
{
    size_t num = 0;
    uint32_t testflags = flags >> 1;
    while (testflags)
    {
        if (testflags & 1) num += getSizeOfTrailingDataEntry(ptr, size - num);
        testflags >>= 1;
    }
    if (flags & 1)
    {
        num += (ptr[size - num - 1] & 0x3) + 1;
    }
    return num;
}
struct MobiSection
{
    uint32_t offset;
    uint32_t flags;
    uint32_t val;
    MobiSection(const char* buffer)
    {
            offset= ((uint32_t)((UCHAR)buffer[0]) << 24) |
                ((uint32_t)((UCHAR)buffer[1]) << 16) |
                ((uint32_t)((UCHAR)buffer[2]) << 8) |
                ((uint32_t)((UCHAR)buffer[3]));
           flags = (UCHAR)buffer[4];
           val = (UCHAR)buffer[5] << 16 | (UCHAR)buffer[6] << 8 | (UCHAR)buffer[7];
        

    }
};
uint32_t unpack_L(const char * buffer, size_t offset = 0) {
    return (static_cast<uint32_t>((UCHAR)buffer[offset]) << 24) |
        (static_cast<uint32_t>((UCHAR)buffer[offset + 1]) << 16) |
        (static_cast<uint32_t>((UCHAR)buffer[offset + 2]) << 8) |
        (static_cast<uint32_t>((UCHAR)buffer[offset + 3]));
}

unsigned char* PC1(const unsigned char* key, unsigned int klen, const unsigned char* src,
    unsigned char* dest, unsigned int len, int decryption)
{
    unsigned int sum1 = 0;
    unsigned int sum2 = 0;
    unsigned int keyXorVal = 0;
    unsigned short wkey[8];
    unsigned int i;
    if (klen != 16) {
        fprintf(stderr, "Bad key length!\n");
        return NULL;
    }
    for (i = 0; i < 8; i++) {
        wkey[i] = (key[i * 2] << 8) | key[i * 2 + 1];
    }
    for (i = 0; i < len; i++) {
        unsigned int temp1 = 0;
        unsigned int byteXorVal = 0;
        unsigned int j, curByte;
        for (j = 0; j < 8; j++) {
            temp1 ^= wkey[j];
            sum2 = (sum2 + j) * 20021 + sum1;
            sum1 = (temp1 * 346) & 0xFFFF;
            sum2 = (sum2 + sum1) & 0xFFFF;
            temp1 = (temp1 * 20021 + 1) & 0xFFFF;
            byteXorVal ^= temp1 ^ sum2;
        }
        curByte = src[i];
        if (!decryption) {
            keyXorVal = curByte * 257;
        }
        curByte = ((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF;
        if (decryption) {
            keyXorVal = curByte * 257;
        }
        for (j = 0; j < 8; j++) {
            wkey[j] ^= keyXorVal;
        }
        dest[i] = curByte;
    }
    return dest;
}
std::vector<char> PC1d(const std::vector<char>&key, const std::vector<char>& vec,int dec)
{
    std::vector<char> temp_key(vec.size());
    PC1((const unsigned char*)&key[0], key.size(), (const unsigned char*)&vec[0], (unsigned char*)&temp_key[0], vec.size(), dec);
    return temp_key;

}

void processChunkedFile(const std::string& filePath) {
    // 1. Open the file for both reading and writing in binary mode
    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
    
    if (!file.is_open()) {
        std::cerr << "Failed to open the file: " << filePath << std::endl;
        return;
    }

    // 2. Define your chunk size (e.g., 4096 bytes / 4 KB)
    const size_t CHUNK_SIZE = 4096;
    std::vector<char> buffer(CHUNK_SIZE);

    // Loop until we hit the end of the file
    while (file) {
        // Record the exact position where this chunk starts
        std::streampos chunkStartPosition = file.tellg();

        // 3. Read a chunk of data
        file.read(buffer.data(), buffer.size());
        std::streamsize bytesRead = file.gcount(); // Get the actual number of bytes read

        if (bytesRead == 0) {
            break; // End of file reached safely
        }

        // 4. Process the data inside the buffer
        for (std::streamsize i = 0; i < bytesRead; ++i) {
            buffer[i] = buffer[i] ^ 0xAA; // Example: Simple XOR operation
        }

        // 5. Seek back to the starting point of the chunk to overwrite it
        file.seekp(chunkStartPosition);

        // 6. Write the modified chunk back to the file
        file.write(buffer.data(), bytesRead);

        // 7. Force a seek/flush to safely transition the stream from Write to Read mode
        file.seekg(file.tellp());
    }

    file.close();
    std::cout << "File processing completed successfully!" << std::endl;
}

std::vector<char> readChunkFromStream(std::fstream& file, std::streamoff offset, size_t chunkSize) 
{
    // 1. Ensure the stream is in a good state before operations
    if (!file.is_open() || !file.good()) {
        std::cerr << "Error: Stream is not open or is in a bad state." << std::endl;
        return {};
    }

    // 2. Clear any lingering EOF or fail flags from prior operations
    file.clear();

    // 3. Move the read pointer (g) to the specified offset from the beginning
    file.seekg(offset, std::ios::beg);
    if (!file) {
        std::cerr << "Error: Failed to seek to offset " << offset << std::endl;
        return {};
    }

    // 4. Allocate memory in the vector
    std::vector<char> buffer(chunkSize);

    // 5. Read directly into the vector's contiguous memory block
    file.read(buffer.data(), buffer.size());
    std::streamsize bytesRead = file.gcount();

    // 6. Resize if we encountered the end of the file early
    if (bytesRead < static_cast<std::streamsize>(chunkSize)) {
        buffer.resize(bytesRead);
    }

    return buffer;
}
std::string readStringFromStream(std::fstream& file, std::streamoff offset, size_t chunkSize)
{
  std::vector<char> chunk=readChunkFromStream(file,offset,chunkSize);
  return std::string(chunk.begin(),chunk.end());
}
class MobiBook : public BookInterface
{

public:
    bool init_done = false;
    int num_sections=0;
    std::string magic;
    std::fstream data_file;
    std::streamsize data_file_size=0;
    //std::vector<char> data_file;
    //std::vector<char> mobi_data;
    std::vector<char> sect;
    //std::vector<char> header;
    std::vector<MobiSection> sections;
    int crypto_type = -1;
    uint16_t records=0;
    uint16_t compression=0;
    bool print_replica=false;
    uint32_t extra_data_flags = 0;
    uint32_t mobi_length = 0;
    uint32_t mobi_codepage = 1252;
    int mobi_version = -1;
    std::map<uint32_t, std::vector<char>> meta_array;
    std::vector<char> loadSection(int section)
    {
        int endoff = 0;
        if (section + 1 == num_sections)
        {
            endoff = data_file_size;
        }
        else
        {
            endoff = sections[section+1].offset;
        }
        int off= sections[section ].offset;
        return readChunkFromStream(data_file,off,endoff-off);//std::vector<char>(data_file.begin() + off, data_file.begin() + endoff);
    }
    void patch(size_t offset, const char* new_data,size_t sz )
    {
        data_file.seekp(offset);
        data_file.write(new_data, sz);
        data_file.seekg(data_file.tellp());
        //memcpy(&data_file[offset], new_data, sz);
    }
    void patchSection(int section, const char* new_data,size_t sz, size_t in_off=0)
    {
        int endoff = 0;
        if (section + 1 == num_sections)
        {
            endoff = data_file_size;
        }
        else
        {
            endoff = sections[section + 1].offset;
        }
        int off = sections[section].offset;
        if (off + in_off + sz > endoff)
        {
            std::cout << "ERROR* mobi patching exceeds data len" << std::endl;
            return;
        }
        patch(off + in_off, new_data, sz);
     }
 
    MobiBook(const fs::path& path):data_file(path, std::ios::in | std::ios::out | std::ios::binary)
    {
        std::cout << "MobiDeDrm Port" << std::endl;
        std::cout<<"Opening "<<path<<std::endl;
         data_file_size = data_file.tellg();
        data_file.seekg(0, std::ios::beg);
        //std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
        
        //read_file_to_vector(path.string(), data_file);
        //data_file = ReadFileToVector(path);
        //std::cout << "Read file of " <<data_file.size() <<std::endl;
        //header.resize(78);
       // memcpy(&header[0],&data_file[0],78);
       /*
       self.header = self.data_file[0:78]
        if self.header[0x3C:0x3C+8] != b'BOOKMOBI' and self.header[0x3C:0x3C+8] != b'TEXtREAd':
            raise DrmException("Invalid file format")
        self.magic = self.header[0x3C:0x3C+8]

       */
        magic = readStringFromStream(data_file,0x3c,8);//std::string(data_file.begin() + 0x3C, data_file.begin() + 0x3C + 8);
        if (magic!= "BOOKMOBI" && magic != "TEXtREAd")
        {
            std::cout << path << " is not a mobi book " << std::endl;
            init_done = false;
            return;
        }

        num_sections = unpack_H(readChunkFromStream(data_file,76,2));//.header[76:78]
        std::cout << "Sections: " <<num_sections <<std::endl;
        for (int i = 0; i < num_sections; i++)
        {
            MobiSection ms(&readChunkFromStream(data_file,78+i*8,8)[0]);//&data_file[78+i*8]);
            sections.push_back(ms);
        }
        sect = loadSection(0);
        records = unpack_H(&sect[8]);
        compression = unpack_H(&sect[0]);
        if (magic == "TEXtREAd")
        {
            std::cout << "PalmDoc format book detected." << std::endl;
            init_done = true;
            return;
        }
        mobi_length = unpack_L(&sect[0x14]);
        mobi_codepage = unpack_L(&sect[0x1c]);
        mobi_version = unpack_L(&sect[0x68]);
        std::cout << "MOBI header version " << mobi_version << ", header length " << mobi_length<< std::endl;
        if (mobi_length >= 0xe4 && mobi_version >= 5)
        {
            extra_data_flags = unpack_H(sect, 0xf2);
        }
        if (compression != 17480)
        {
            extra_data_flags &= 0xFFFE;
        }
        if (sect.size() >= 0x84)
        {
            uint32_t exth_flag= unpack_L(&sect[0x80]);
            std::vector<char> exth;
            if (exth_flag & 0x40&&sect.size()>16+mobi_length)
            {
                exth = std::vector<char>(sect.begin()+16+mobi_length,sect.end());
                if (exth.size() > 12 && exth[0] == 'E' && exth[1] == 'X' && exth[2] == 'T' && exth[3] == 'H')
                {
                    uint32_t nitems = unpack_L(&exth[8]);
                    uint32_t pos = 12;
                    for (uint32_t i = 0; i < nitems; i++)
                    {
                        uint32_t type= unpack_L(&exth[pos]);
                        uint32_t size = unpack_L(&exth[pos+4]);
                        std::vector<char> content(exth.begin()+8+pos, exth.begin()+size+pos);
                        meta_array[type] = content;
                        if (type == 401 && size == 9)
                        {
                            char b = 144;
                            patchSection(0, &b, 1, 16 + mobi_length + pos + 8);
                        }
                        if (type == 404 && size == 9)
                        {
                            char b = 0;
                            patchSection(0, &b, 1, 16 + mobi_length + pos + 8);
                        }
                        if (type == 405 && size == 9)
                        {
                            char b = 0;
                            patchSection(0, &b, 1, 16 + mobi_length + pos + 8);
                            
                        }
                        if (type == 406 && size == 16)
                        {
                            char b[8] = { 0,0,0,0,0,0,0,0 };
                            patchSection(0, b, 8, 16 + mobi_length + pos + 8);
                        }
                        if (type == 208)
                        {
                            std::vector<char> b;
                            b.resize(size-8);
                            patchSection(0, &b[0], 8, 16 + mobi_length + pos + 8);
                        }
                        pos += size;
                    }
                }
            }
        }
        init_done = true;
    }
    virtual ~MobiBook() {};
    virtual std::string getBookType() { return "MOBI"; }
    virtual std::string getBookExtension() 
    { 
        if (print_replica)
        {
            return ".azw4";
        }
        if (mobi_version >= 8)
        {
            return ".azw3";
        }
        return ".mobi";
    }
    virtual void writeFile(const fs::path& fl) 
    {
       // writeFileBasic(fl, mobi_data);
    };
    virtual std::pair<std::vector<char>, std::vector<char>> getPIDMetaInfo()
    { 
        std::vector<char> rec209;
        std::vector<char> token;
       
        auto fnd = meta_array.find(209);
        if (fnd != meta_array.end())
        {
            rec209 = fnd->second;
            token.clear();
            for (int i = 0; i < rec209.size(); i+=5)
            {
                uint32_t val = unpack_L(&rec209[i+1]);
                auto fval = meta_array.find(val);
                if (fval != meta_array.end())
                {
                    token = ccat(token, fval->second);
                }
            }
        }
        return { rec209, token };
    
    }
    std::pair<std::vector<char>, std::string>  parseDRM(const char * data,int count,const std::vector<std::string>& pidlist)
    {
        std::vector<char> found_key;
        std::string fpid = "";
        std::vector<char> keyvec1 = HexToBytesC("723833b0b4f2e3cadf0901d6e2e03f96");
        for (auto pid : pidlist)
        {
            std::string bigpid(16, '\0');
            size_t copy_size = std::min(pid.length(), size_t(16));
            bigpid.replace(0, copy_size, pid, 0, copy_size);
            std::vector<char> bp(bigpid.begin(),bigpid.end());
            //unsigned char* PC1(const unsigned char* key, unsigned int klen, const unsigned char* src,
             //   unsigned char* dest, unsigned int len, int decryption)
            //temp_key = PC1(keyvec1, bigpid, False)

            std::vector<char> temp_key = PC1d(keyvec1, bp, 0);
            int temp_key_sum = 0;
            for (auto c : temp_key)
            {
                temp_key_sum += (UCHAR)c;
            }
            temp_key_sum &= 0xff;
            found_key.clear();
            for (int i = 0; i < count; i++)
            {
                uint32_t verification = unpack_L(&data[i * 0x30]);
                uint32_t size = unpack_L(&data[i * 0x30+4]);
                uint32_t type = unpack_L(&data[i * 0x30 + 8]);
                char cksum = data[i * 0x30 + 12];
                std::vector<char> cookie(&data[i * 0x30 + 16], &data[i * 0x30 + 16 + 32]);
                if ((UCHAR)cksum == (UCHAR)temp_key_sum)
                {
                    cookie = PC1d(temp_key, cookie, 1);
                    /*
                    ver,flags,finalkey,expiry,expiry2 = struct.unpack('>LL16sLL', cookie)
                    if verification == ver and (flags & 0x1F) == 1:
                        found_key = finalkey
                        break
                    */
                    uint32_t ver = unpack_L(&cookie[0]);
                    uint32_t flags = unpack_L(&cookie[4]);
                    std::vector<char> finalkey(cookie.begin()+8, cookie.begin() + 8+16);
                    if (ver == verification && (flags & 0x1f) == 1)
                    {
                        found_key = finalkey;
                        fpid = pid;
                        break;
                    }
                }
                
            }
            if (found_key.size() > 0)
            {
                break;
            }
        }
        if (found_key.size() == 0)
        {
            std::string  pid = "00000000";
            std::vector<char> temp_key = keyvec1;
            int temp_key_sum = 0;
            for (auto c : temp_key)
            {
                temp_key_sum += (UCHAR)c;
            }
            temp_key_sum &= 0xff;
            for (int i = 0; i < count; i++)
            {
                uint32_t verification = unpack_L(&data[i * 0x30]);
                uint32_t size = unpack_L(&data[i * 0x30 + 4]);
                uint32_t type = unpack_L(&data[i * 0x30 + 8]);
                char cksum = data[i * 0x30 + 9];
                std::vector<char> cookie(&data[i * 0x30 + 12], &data[i * 0x30 + 12 + 32]);
                if (cksum == temp_key_sum)
                {
                    cookie = PC1d(temp_key, cookie, 1);
                    uint32_t ver = unpack_L(&cookie[0]);
                    uint32_t flags = unpack_L(&cookie[4]);
                    std::vector<char> finalkey(cookie.begin() + 8, cookie.begin() + 8 + 16);
                    if (ver == verification && (flags & 0x1f) == 1)
                    {
                        found_key = finalkey;
                        fpid = pid;
                        break;
                    }
                }

            }
        }
        return { found_key,fpid };
    }
    virtual void processBook(const std::vector<std::string>& pids) 
    {
        crypto_type = unpack_H(&sect[0xc]);
        std::cout << "Crypto type is " << crypto_type << std::endl;
        if (crypto_type == 0)
        {
            std::cout << "Book is not encrypted " << std::endl;
            std::vector<char> sec1 = loadSection(1);
            print_replica = (sec1[0] == '%' && sec1[1] == 'M' && sec1[2] == 'O' && sec1[3] == 'P');
           //mobi_data = data_file;
            return;
        }
        if (crypto_type != 2 && crypto_type != 1)
        {
            throw DrmException("Cannot decode unknown Mobipocket encryption type");
        }
        std::vector<std::string> goodpids;
        for (auto pid : pids)
        {
            if (pid.size() == 8)
            {
                goodpids.push_back(pid);
            }
            if (pid.size() == 10)
            {
                std::string ck = checksumPID(pid.substr(0, 8));
                if (ck != pid)
                {
                    std::cout << "Warning PID checksum does not match: old: " << pid << " new: " << ck<<std::endl;
                }
                goodpids.push_back(pid.substr(0, 8));
            }
        }
        std::string fpid;
        std::vector<char> found_key;
        if (crypto_type == 1)
        {
            std::vector<char> t1_keyvec = HexToBytesC("5144435645504d55363735525542535a");
            std::vector<char> bookkey_data;
            if (magic == "TEXtREAd")
            {
                bookkey_data = std::vector<char>(sect.begin()+0xe, sect.begin() + 0xe + 16);
            }
            else
            {
                if (mobi_version < 0)
                {
                    bookkey_data = std::vector<char>(sect.begin() + 0x90, sect.begin() + 0x90 + 16);
                }
                else
                {
                    bookkey_data = std::vector<char>(sect.begin() + 16+ mobi_length, sect.begin() + mobi_length + 32);
                }

            }
            fpid = "00000000";
            found_key = PC1d(t1_keyvec, bookkey_data,1);
        }
        else
        {
            uint32_t drm_ptr = unpack_L(&sect[0xa8]);
            uint32_t drm_count = unpack_L(&sect[0xa8+4]);
            uint32_t drm_size = unpack_L(&sect[0xa8 + 8]);
           // uint32_t drm_flags = unpack_L(&sect[0xa8 + 12]);
            if (drm_count == 0)
            {
                throw DrmException("MOBI Encryption not initialised.");
            }
            std::pair<std::vector<char>, std::string> fkp = parseDRM(&sect[drm_ptr], drm_count, goodpids);
            if (fkp.first.size() == 0)
            {
                std::cout << "Tried  " << goodpids.size() << " PIDS " << std::endl;
                throw DrmException("No key found");
            }
            found_key = fkp.first;
            fpid = fkp.second;
            std::vector<char> b;
            b.resize(drm_size);
            patchSection(0, &b[0], drm_size, drm_ptr);
            b.resize(16);
            b[0] = 0xff;
            b[1] = 0xff;
            b[2] = 0xff;
            b[3] = 0xff;
            patchSection(0, &b[0], 16, 0xA8);
        }
        if (fpid == "00000000")
        {
            std::cout << "File has default encryption, no specific key needed." << std::endl;
        }
        else
        {
            std::cout << "File is encoded with PID " <<fpid<< std::endl;
        }
        uint16_t ss = 0;
        patchSection(0, (const char*)&ss, 2, 0xC);
        std::cout << "Decrypting..." << std::endl;
       // std::vector<std::vector<char>> mobidataList;
        //mobidataList.push_back(std::vector<char>(data_file.begin(), data_file.begin()+sections[1].offset));
        for (int i = 1; i < records + 1; i++)
        {
            std::vector<char> data = loadSection(i);
            size_t extra_size = getSizeOfTrailingDataEntries(&data[0], data.size(), extra_data_flags);
            std::vector<char> truncated = std::vector<char>(data.begin(), data.begin() + data.size()-extra_size);
            std::vector<char> decoded_data = PC1d(found_key, truncated, 1);
            print_replica = (decoded_data[0] == '%' && decoded_data[1] == 'M' && decoded_data[2] == 'O' && decoded_data[3] == 'P');
            //mobidataList.push_back(decoded_data);
            patchSection(i, &decoded_data[0],decoded_data.size(),0);
            //patch();
           // if (extra_size > 0)
            //{
            //    mobidataList.push_back(std::vector<char>( data.begin() + data.size() - extra_size,data.end()));
           // }
        }
        //if (num_sections > records + 1)
       //{
        //    mobidataList.push_back(std::vector<char>(data_file.begin()+ sections[records + 1].offset, data_file.end()));
       // }
       // size_t totalSize = 0;
        //for (const auto& subVector : mobidataList) {
         //   totalSize += subVector.size();
        //}
        //mobi_data.reserve(totalSize);

        // 3. Append each inner vector to the single flat vector
        //for (const auto& subVector : mobidataList) {
         //   mobi_data.insert(mobi_data.end(), subVector.begin(), subVector.end());
        //}
        std::cout << "Done parsing MOBI" << std::endl;
    }
    virtual void cleanup() {}
};

int main(int argc, char *argv[])
{
  printf("Kindle reader , %d arguments\n", argc);
  std::vector<fs::path> infolders;
  std::vector<fs::path> infiles;
  std::vector<fs::path> mobifiles;
  fs::path out_folder{"/mnt/us/dedrm"};
  infolders.push_back(fs::path("/mnt/us/documents"));

  std::string jdsn;
  std::vector<std::string> jsecrets;
  std::string mode="decrypt_all";
  fs::path sngl;
  bool truncate=false;
  if (argc>1)
  {
    std::string cmd=argv[1];
    if(cmd=="test") mode="test";
    if(cmd=="scan") mode="scan";
    if(cmd=="scantruncate") {mode="scan";truncate=true;}
    if(cmd=="keyfile") mode="keyfile";
    if(cmd=="dedrm") 
    {
      if(argc<3)
      {
        printf("Requires two arguments, command and book name\n");
        return 2;
      }
      mode="decrypt_one";
      sngl=fs::path(std::string(argv[2]));
    }
  }

  if(mode=="scan")
  {
    for (auto &inpath : infolders)
    {
    scan_folder_for_book_candidates(inpath, infiles);
    mobi_scan(inpath, infiles);
    }
    updatemenufile(infiles,truncate);
    return 0;
  }
  // open shared library
  fs::path libPath;
  void *prn =  dlopen("libYJSDK-shared.so", RTLD_LAZY);//dlopen("/mnt/us/extensions/kfxdedrm/bin/libYJSDK-voyage-shared.so", RTLD_LAZY);;//
  if (prn == nullptr)
  {
    printf("Could not open shared library at :  %s\n", dlerror());
    return 2;
  }
  typedef void (*getinst)(std::shared_ptr<void*>&res);
  getinst getsec=(getinst)dlsym(prn, "_ZN5yjsdk13IBookSecurity11getInstanceERSt10shared_ptrIS0_E");
  if(getsec==nullptr)
  {
    printf("Could not get book security normally, trying older function\n");
    getsec=(getinst)dlsym(prn, "_ZN5yjsdk13IBookSecurity11getInstanceERNS_9SharedPtrIS0_EE");
    if (getsec==nullptr)
    {
      printf("Could not find security getInstance,bailing\n");
      return 3;
    }
  }
   std::shared_ptr<void*> booksec;
  getsec(booksec);
  if(booksec.get()==nullptr)
  {
    printf("Could not get booksec");
    return 3;
  }
  void** vtable=*(void***)booksec.get();
  typedef void (*setParams)( void*,std::map<std::string,std::vector<std::string>>&p);
  setParams setSec=(setParams)vtable[4];
  typedef int (*attachVouch)( void*,const char* );
  attachVouch attachv=(attachVouch)vtable[5];
  std::string clientid=read_file_to_string("/proc/usid");
  trim(clientid);
  remove_non_alphanumeric(clientid);
  void *pv = dlsym(prn, "_ZN5yjsdk11BookFactory7getBookEPKcSt10shared_ptrINS_13IBookSecurityEERS3_INS_12IDigitalBookEE");
  if(pv==nullptr)
  {
    printf("Could not find getBook normally, trying older function\n");
    pv = dlsym(prn,"_ZN5yjsdk11BookFactory7getBookEPKcNS_9SharedPtrINS_13IBookSecurityEEERNS3_INS_12IDigitalBookEEE");
    if(pv==nullptr)
    {
    printf("Could not find getBook, check libYJSDK-shared.so library variant\n");
    return 4;
    }
  }
  if(mode=="test")
  {
    std::map<std::string,std::vector<std::string>> testpars;
    std::vector<std::string> clientids;
    std::vector<std::string> fakesecrets;
    fakesecrets.push_back("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    fakesecrets.push_back("ffffffffffffffffffffffffffffffff");
    clientids.push_back(clientid);
    testpars["CLIENT_ID"]=clientids;
    testpars["ACCOUNT_SECRET"]=fakesecrets;
    setSec(booksec.get(),testpars); //it would throw if incompatible, hopefully;
    return 0;
  }
  
  std::cout << "Selected Out folder: " << out_folder << std::endl;

  // prep output folder
  if (!fs::exists(out_folder))
  {
    fs::create_directory(out_folder);
    std::cout << "Created directory: " << out_folder << std::endl;
  }
  if (!fs::is_directory(out_folder))
  {
    printf("Output folder %s could not be created or is a file\n", out_folder.string().c_str());
    return -3;
  }
  

  

// ibooksec getinstance _ZN5yjsdk13IBookSecurity11getInstanceERSt10shared_ptrIS0_E
 
  
  std::string sz="sizelarge";
  printf("usid length %zu string legnth: %zu\n",clientid.size(),sizeof(sz));
  std::map<std::string,std::vector<std::string>> secpars;
  std::vector<std::string> cl1;
  std::string secrcomb=read_file_to_string("/var/local/java/prefs/acsr");
  std::vector<std::string> asecrets;
  std::cout << "DSN " <<clientid <<std::endl;
  if(secrcomb.size()>2)
  {
    asecrets=split_secrets(secrcomb);
    for(auto& sec:asecrets)
    {
      std::cout << "Secr: " << sec << std::endl;
      secret_candidates.insert(sec);
    }
  }
  cl1.push_back(clientid);
  secpars["CLIENT_ID"]=cl1;
  secpars["ACCOUNT_SECRET"]=asecrets;
  install_hook((void*)getsec);
  
  printf("Booksec: %p\n",booksec.get());
  
  printf("Vtable: %p\n",vtable);
  
  printf("Found getbook %p \n", pv);
 
 typedef int (*getbook1)(const char *,std::shared_ptr<void*>&booksec, std::shared_ptr<void*>&);
  getbook1 gb=(getbook1)pv;
  if(mode=="decrypt_one")
  {
    infiles.clear();
    if(sngl.extension()==".kfx")
    {
      infiles.push_back(sngl);
    }
    else 
    {
      mobifiles.push_back(sngl);
    }
    
  }
  
  if(mode=="decrypt_all" ||mode=="keyfile")
  {
  for (auto &inpath : infolders)
  {
    scan_folder_for_book_candidates(inpath, infiles);
    mobi_scan(inpath, mobifiles);
  }
  }
std::ofstream outkeyfile;
 if(mode=="keyfile")
 {
   outkeyfile.open("/mnt/us/dedrm/keyfile.txt");
 }
   {
     std::cout <<"Trying to induce secrets with fake book" <<std::endl;
     fs::path fbook=fs::path("/mnt/us/dedrm/");
      fs::path fb_path_v = fbook / "fake.voucher";
      fs::path fb_path_a = fbook / "fake.kfx";
      write_vector_to_file(fb_path_v, fake);
      write_vector_to_file(fb_path_a, drmionHeader);
       std::shared_ptr<void*> nbook=nullptr;
       std::shared_ptr<void*> nbooksec=nullptr;
       getsec(nbooksec);
       setSec(nbooksec.get(),secpars);
       printf("Attaching fake voucher: %d\n",attachv(nbooksec.get(),fb_path_v.string().c_str()));
         int res= gb(fb_path_a.string().c_str(),nbooksec,nbook);
      printf("Open fake book result: %d \n",res);
      std::remove(fb_path_v.string().c_str());
      std::remove(fb_path_a.string().c_str());
       
  }
  key_candidates.clear();
  for (auto &itm : infiles)
  {
    fs::path metadata_path = itm ;
    std::string bookid = itm.stem().string();
    std::cout << bookid << std::endl;
    std::map<std::string, std::vector<fs::path>> metadata;
    fs::path output_path = out_folder / fs::path(bookid + ".kfx-zip");
    if(fs::is_regular_file(output_path))
    {
      std::cout << "Archive " <<output_path<< " already exists, skipping... Delete it if you want to rerun. " << std::endl;
      continue;
    }
    if (process_assets(bookid, itm, metadata))
    {
      key_candidates.clear();
       std::shared_ptr<void*> nbook=nullptr;
       std::shared_ptr<void*> nbooksec=nullptr;
       getsec(nbooksec);
       setSec(nbooksec.get(),secpars);
       for(auto&v:metadata["vouchers"])
       {
        printf("Attaching voucher: %d\n",attachv(nbooksec.get(),v.string().c_str()));
       }
       std::cout << metadata["bookFiles"][0]<<std::endl;
      int res= gb(metadata["bookFiles"][0].string().c_str(),nbooksec,nbook);
      printf("Open book result: %d \n",res);
       nbook=nullptr;
       nbooksec=nullptr;
      if(res!=0)
      {
        printf("Could not open book, skipping \n");
        continue;
      }
      allocations.clear();
      std::vector<std::vector<uint8_t>> keyset(key_candidates.begin(), key_candidates.end());
      std::cout << keyset.size() << " key candidates" << std::endl;
      bool no_enc=false;
      if(keyset.size()==0) 
      {
        no_enc=true;
        std::vector<uint8_t> dummy(16);
        keyset.push_back(dummy);
      }
      std::string keyname;
      std::vector<std::vector<uint8_t>> result = test_drmions_for_keys(metadata["resources"], keyset,keyname);
      std::cout <<"Key name: " <<keyname <<std::endl;
      if (result.size() == 1)
      {

        std::cout << "Found key: " << hexStr(result[0].data(), 16) << std::endl;
        if(mode=="keyfile")
        {
          if(!no_enc)
          {
        printf("Adding to keyfile\n");
        outkeyfile << keyname<<"$secret_key:"<< hexStr(result[0].data(), 16) <<std::endl;
          }
         
        }
        else 
        {
        AesDecryptor decr(result[0]);
        
        std::cout << "Generating " << output_path << std::endl;
        std::cout << "Removal result " << std::remove(output_path.string().c_str()) << std::endl; // clear if exists
        for (auto fl : metadata["resources"])
        {
          processFile(output_path.string().c_str(), fl.string(), fl.filename().string(), &decr);
        }
        }
        printf("Book processed \n");
      }

      printf("Done opening book ~~ \n");
    }
    else
    {
      std::cout << "Invalid or unsupported metadata" << std::endl;
    }
  }
  
  
  
  
   if(mode=="keyfile")
 {
   outkeyfile.close();
 }
 //MOBI
 if(mode=="decrypt_all"||mode=="decrypt_one")
 {
   if(mobifiles.size()>0)
   {
     for(auto mobipath:mobifiles)
     {
       std::cout << "Copying " <<mobipath <<" for inplace processing "<<std::endl;
        fs::path out_path = fs::path("/mnt/us/dedrm/") / mobipath.filename();
        bool success = fs::copy_file(mobipath, out_path, fs::copy_options::overwrite_existing);
       
         MobiBook mb(out_path);
         if (!mb.init_done)
         {
             std::cout << "Seems like it is not mobi, cannot decrypt. Might be Topaz? " << out_path <<std::endl;
         }
         else
         {
           std::cout << "Opened MOBI" <<std::endl;
             try
             {
                 auto pdd = mb.getPIDMetaInfo();
                 std::cout << "Got info " <<pdd.first.size() << "  " << pdd.second.size()<<std::endl;
                 std::vector<std::string> sec;
                 for (auto osc : secret_candidates)
                 {
                     sec.push_back(osc);
                 }
                 std::vector<std::string> pidz = getK4Pids(pdd.first, pdd.second, clientid, sec);
                 std::cout << "Got pidz " <<pidz.size()<<std::endl;
                 mb.processBook(pidz);
                 
                 std::cout << "Looks like it processed... Saving to " << out_path << std::endl;
                 mb.data_file.close();
                 std::cout <<"Saved!"<<std::endl;
                 //mb.writeFile(out_path);

             }
             catch (DrmException e)
             {
                 std::cout << "Failed MOBI processing: " << e.what() << std::endl;
                 std::remove(out_path.string().c_str());
             }

         }
     }
   }
 }
  printf("DeDRM all done.\n");
}
