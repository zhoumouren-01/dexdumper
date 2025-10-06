#ifndef DEXDUMPER_SHA1_H
#define DEXDUMPER_SHA1_H

// SHA1 hashing header - declares cryptographic hash functions for duplicate detection

#include "common.h"
#include "config.h"

/**
 * SHA1 Context Structure:
 * 
 * Maintains state during hash computation including intermediate hash values
 * and buffered data.
 */
typedef struct {
    uint32_t h0, h1, h2, h3, h4;  // Intermediate hash values
    uint8_t buffer[64];            // Input data buffer (512 bits)
    uint32_t buffer_len;           // Current bytes in buffer
    uint64_t total_len;            // Total bytes processed
} sha1_context;

/**
 * SHA1 Hashing Functions:
 * 
 * Implementation of SHA1 cryptographic hash algorithm for duplicate detection.
 * Used to identify identical DEX files even if they appear in different memory regions.
 */

// Initializes SHA1 context for new computation
void sha1_init(sha1_context *ctx);

// Updates hash with new data
void sha1_update(sha1_context *ctx, const uint8_t *data, size_t len);

// Finalizes hash computation and produces digest
void sha1_final(sha1_context *ctx, uint8_t *digest);

// Convenience function to compute SHA1 for single data buffer
void compute_sha1_checksum(const void *data, size_t data_size, uint8_t *digest);

// Compares two SHA1 digests for equality
int compare_sha1_digests(const uint8_t *digest1, const uint8_t *digest2);

// Converts binary digest to hexadecimal string representation
void sha1_to_hex_string(const uint8_t *digest, char *output, size_t output_size);

#endif