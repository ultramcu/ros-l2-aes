// crypto.cpp — AES-CBC encrypt/decrypt + uppercase hex codec.
// See include/crypto.h for the API contract.
//
// Implementation notes:
//
//   - Uses OpenSSL's legacy <openssl/aes.h> low-level API (not EVP_*)
//     to match the paper. On Linux ARM64 + macOS arm64 (via Parallels)
//     OpenSSL >= 1.1.1 still dispatches the legacy AES_cbc_encrypt
//     through aes_v8_*, which means the ARMv8 Cryptography Extensions
//     are used transparently.
//
//   - CBC mode with a fixed IV per key length (loaded from
//     config/keys.h). Reusing a fixed IV is acceptable inside the paper
//     experiment because each message has a distinct timestamp / type
//     wrapping it in JSON; do not lift the AES routines out of this
//     context without revisiting IV handling.
//
//   - Padding is manual zero-extension to the next 16-byte boundary.
//     Plaintext of N bytes ends up as ceil(N / 16) * 16 bytes of
//     ciphertext. Callers track the original length out of band (the
//     JSON envelope built in main.cpp carries it).

#include "../include/crypto.h"

#include <cstring>
#include <iomanip>
#include <sstream>

#include "../config/keys.h"

namespace {

// Round src_len up to the next AES block boundary (16 bytes).
inline uint32_t alignToBlock(uint32_t src_len) {
    const uint8_t rem = src_len % AES_BLOCK_SIZE;
    return rem == 0 ? src_len : src_len + (AES_BLOCK_SIZE - rem);
}

// Zero the destination buffer up to dst_size, then run AES-CBC.
// key_bytes points at the key material; key_bits is its length in bits
// (128 / 192 / 256). iv_bytes points at a 16-byte IV (AES block size is
// always 16 bytes regardless of key length).
uint32_t aesCbcEncrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size,
                       const uint8_t* key_bytes, int key_bits, const uint8_t* iv_bytes) {
    if (dst_size < src_len) {
        return 0;
    }
    const uint32_t padded_len = alignToBlock(src_len);

    std::memset(dst, 0, dst_size);

    unsigned char iv[AES_BLOCK_SIZE];
    std::memcpy(iv, iv_bytes, AES_BLOCK_SIZE);

    AES_KEY enc_key;
    AES_set_encrypt_key(key_bytes, key_bits, &enc_key);
    AES_cbc_encrypt(src, dst, padded_len, &enc_key, iv, AES_ENCRYPT);
    return padded_len;
}

uint32_t aesCbcDecrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size,
                       const uint8_t* key_bytes, int key_bits, const uint8_t* iv_bytes) {
    if (dst_size < src_len) {
        return 0;
    }
    std::memset(dst, 0, dst_size);

    unsigned char iv[AES_BLOCK_SIZE];
    std::memcpy(iv, iv_bytes, AES_BLOCK_SIZE);

    AES_KEY dec_key;
    AES_set_decrypt_key(key_bytes, key_bits, &dec_key);
    AES_cbc_encrypt(src, dst, src_len, &dec_key, iv, AES_DECRYPT);
    return src_len;
}

inline uint8_t hexCharToValue(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    return 0;
}

}  // namespace

// ---------------------------------------------------------------------
// AES-128
// ---------------------------------------------------------------------

uint32_t aes128Encrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size) {
    return aesCbcEncrypt(src, src_len, dst, dst_size,
                         AES_KEY_128, sizeof(AES_KEY_128) * 8, AES_IV_128);
}

uint32_t aes128Decrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size) {
    return aesCbcDecrypt(src, src_len, dst, dst_size,
                         AES_KEY_128, sizeof(AES_KEY_128) * 8, AES_IV_128);
}

// ---------------------------------------------------------------------
// AES-256
// ---------------------------------------------------------------------

uint32_t aes256Encrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size) {
    return aesCbcEncrypt(src, src_len, dst, dst_size,
                         AES_KEY_256, sizeof(AES_KEY_256) * 8, AES_IV_256);
}

uint32_t aes256Decrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size) {
    return aesCbcDecrypt(src, src_len, dst, dst_size,
                         AES_KEY_256, sizeof(AES_KEY_256) * 8, AES_IV_256);
}

// ---------------------------------------------------------------------
// AES-512 — DEPRECATED
// ---------------------------------------------------------------------
//
// AES does not specify a 512-bit key mode. The original code passed a
// 512-bit key length to AES_set_encrypt_key, which returns -2 ("bad
// key length") and leaves the key schedule undefined; downstream
// AES_cbc_encrypt then operated on uninitialised round keys. That path
// produced ciphertext but was not real AES and was not invertible
// across builds.
//
// We keep the symbols so callers from earlier paper revisions still
// link, but delegate to aes256Encrypt / aes256Decrypt and document the
// removal. New code MUST use aes256Encrypt / aes256Decrypt directly.

uint32_t aes512Encrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size) {
    // [DEPRECATED] AES has no 512-bit mode — delegating to AES-256.
    // TODO: remove call sites and then remove this stub.
    return aes256Encrypt(src, src_len, dst, dst_size);
}

uint32_t aes512Decrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size) {
    // [DEPRECATED] AES has no 512-bit mode — delegating to AES-256.
    // TODO: remove call sites and then remove this stub.
    return aes256Decrypt(src, src_len, dst, dst_size);
}

// ---------------------------------------------------------------------
// Hex codec
// ---------------------------------------------------------------------

std::string bytesToHex(const uint8_t* array, size_t size) {
    static constexpr char hex_digits[] = "0123456789ABCDEF";
    std::string out(size * 2, ' ');
    for (size_t i = 0; i < size; ++i) {
        out[2 * i] = hex_digits[(array[i] >> 4) & 0x0F];
        out[2 * i + 1] = hex_digits[array[i] & 0x0F];
    }
    return out;
}

uint32_t hexToBytes(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t /*dst_size*/) {
    uint32_t j = 0;
    for (uint32_t i = 0; i + 1 < src_len; i += 2, ++j) {
        dst[j] = static_cast<uint8_t>((hexCharToValue(src[i]) << 4) | hexCharToValue(src[i + 1]));
    }
    return j;
}

uint8_t hexCharsToByte(uint8_t high_char, uint8_t low_char) {
    return static_cast<uint8_t>((hexCharToValue(static_cast<char>(high_char)) << 4) |
                                 hexCharToValue(static_cast<char>(low_char)));
}
