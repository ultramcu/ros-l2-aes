// crypto.h — AES-CBC encrypt/decrypt and hex codec for the Layer-2
// ROS topic encryption pipeline described in:
//
//   Tanadechopon T., Kasemsontitum B.
//   "Proposed technique for Data Security with the AES Algorithm in
//   Robot Operating System (ROS)."
//   https://ieeexplore.ieee.org/document/10329645
//
// Key + IV material is loaded from config/keys.h (git-ignored — copy
// keys.example.h to keys.h and fill in your own bytes before building).
//
// API:
//   aes128Encrypt / aes128Decrypt   — AES-128 CBC, 16-byte key + 16-byte IV
//   aes256Encrypt / aes256Decrypt   — AES-256 CBC, 32-byte key + 16-byte IV
//   aes512Encrypt / aes512Decrypt   — DEPRECATED, see notes in crypto.cpp
//   bytesToHex / hexToBytes         — uppercase hex codec
//
// All encrypt/decrypt functions return the number of bytes written into
// dst, or 0 on failure (dst buffer too small). src_len is padded up to
// the next 16-byte boundary with zeros before encryption; callers that
// need to recover the exact original length must track it separately.

#ifndef CRYPTO_INCLUDE_CRYPTO_H_
#define CRYPTO_INCLUDE_CRYPTO_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include <openssl/aes.h>

// ---------------------------------------------------------------------
// AES-CBC encrypt / decrypt
// ---------------------------------------------------------------------

uint32_t aes128Encrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);
uint32_t aes128Decrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);

uint32_t aes256Encrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);
uint32_t aes256Decrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);

// DEPRECATED: AES does not specify a 512-bit key mode (only 128 / 192 /
// 256). These stubs delegate to the AES-256 variants and exist only for
// backward source compatibility with earlier paper revisions. New code
// should call aes256Encrypt / aes256Decrypt directly.
uint32_t aes512Encrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);
uint32_t aes512Decrypt(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);

// ---------------------------------------------------------------------
// Hex codec
// ---------------------------------------------------------------------

// Encode `size` raw bytes as a 2*size uppercase hex string (e.g.
// {0x5E, 0x2D} -> "5E2D"). Allocation-free in the common case (single
// std::string construction).
std::string bytesToHex(const uint8_t* array, size_t size);

// Decode a hex string at `src` (length `src_len`, must be even) into
// `dst` (capacity `dst_size`). Returns the number of decoded bytes
// (= src_len / 2). Accepts both uppercase and lowercase hex digits;
// any non-hex character contributes zero nibbles (mirrors the
// behaviour of the original loop kept from the paper experiment).
uint32_t hexToBytes(uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_size);

// Decode a single byte from two hex characters (high then low nibble).
// Used by callers that decode one byte at a time without building a
// full destination buffer first.
uint8_t hexCharsToByte(uint8_t high_char, uint8_t low_char);

#endif  // CRYPTO_INCLUDE_CRYPTO_H_
