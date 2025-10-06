#include "sha1.h"

/**
 * @brief Initializes SHA1 context with initial hash values
 * 
 * Sets up the initial state for SHA1 computation as defined in the standard.
 * These magic numbers are the initial hash values for SHA1.
 * 
 * @param ctx SHA1 context to initialize
 */
void sha1_init(sha1_context *ctx) {
    // SHA1 initialization constants (from RFC 3174)
    ctx->h0 = 0x67452301;
    ctx->h1 = 0xEFCDAB89;
    ctx->h2 = 0x98BADCFE;
    ctx->h3 = 0x10325476;
    ctx->h4 = 0xC3D2E1F0;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

/**
 * @brief Performs left rotation operation
 * 
 * Helper function for SHA1 that rotates bits left by specified amount.
 * 
 * @param value 32-bit value to rotate
 * @param shift Number of bits to rotate (1-31)
 * @return Rotated value
 */
static uint32_t sha1_rotate_left(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

/**
 * @brief Processes a 512-bit block through SHA1 compression function
 * 
 * This is the core SHA1 algorithm that processes one 512-bit block
 * and updates the hash state.
 * 
 * @param ctx SHA1 context
 * @param block 64-byte block to process
 */
static void sha1_process_block(sha1_context *ctx, const uint8_t *block) {
    uint32_t w[80]; // Message schedule array
    
    // Break block into sixteen 32-bit big-endian words
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    
    // Extend the sixteen 32-bit words into eighty 32-bit words
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rotate_left(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    // Initialize working variables with current hash value
    uint32_t a = ctx->h0;
    uint32_t b = ctx->h1;
    uint32_t c = ctx->h2;
    uint32_t d = ctx->h3;
    uint32_t e = ctx->h4;
    
    // Main compression loop (80 rounds)
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        
        // Choose function and constant based on round
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        
        // SHA1 compression function
        uint32_t temp = sha1_rotate_left(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rotate_left(b, 30);
        b = a;
        a = temp;
    }
    
    // Add compressed chunk to current hash value
    ctx->h0 += a;
    ctx->h1 += b;
    ctx->h2 += c;
    ctx->h3 += d;
    ctx->h4 += e;
}

/**
 * @brief Updates SHA1 context with new data
 * 
 * Processes input data in chunks, calling the compression function
 * for each complete 512-bit block.
 * 
 * @param ctx SHA1 context to update
 * @param data Input data to hash
 * @param len Length of input data
 */
void sha1_update(sha1_context *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    
    // Process data in 64-byte (512-bit) chunks
    while (len > 0) {
        size_t copy_len = 64 - ctx->buffer_len;
        if (copy_len > len) copy_len = len;
        
        // Copy data into buffer
        memcpy(ctx->buffer + ctx->buffer_len, data, copy_len);
        ctx->buffer_len += copy_len;
        data += copy_len;
        len -= copy_len;
        
        // Process block when buffer is full
        if (ctx->buffer_len == 64) {
            sha1_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

/**
 * @brief Finalizes SHA1 computation and produces digest
 * 
 * Applies padding and processes final block(s), then produces
 * the final 160-bit (20-byte) hash value.
 * 
 * @param ctx SHA1 context to finalize
 * @param digest Output buffer for 20-byte hash
 */
void sha1_final(sha1_context *ctx, uint8_t *digest) {
    // Calculate original message length in bits
    uint64_t bit_len = ctx->total_len * 8;
    
    // Append padding bit (0x80)
    ctx->buffer[ctx->buffer_len++] = 0x80;
    
    // Handle case where padding doesn't fit in current block
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < 64) {
            ctx->buffer[ctx->buffer_len++] = 0x00;
        }
        sha1_process_block(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    
    // Pad with zeros until length field
    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0x00;
    }
    
    // Append 64-bit length in big-endian
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }
    sha1_process_block(ctx, ctx->buffer);
    
    // Produce final hash value (big-endian)
    for (int i = 0; i < 4; i++) {
        digest[i] = (ctx->h0 >> (24 - i * 8)) & 0xFF;
        digest[i + 4] = (ctx->h1 >> (24 - i * 8)) & 0xFF;
        digest[i + 8] = (ctx->h2 >> (24 - i * 8)) & 0xFF;
        digest[i + 12] = (ctx->h3 >> (24 - i * 8)) & 0xFF;
        digest[i + 16] = (ctx->h4 >> (24 - i * 8)) & 0xFF;
    }
}

/**
 * @brief Computes SHA1 checksum for given data
 * 
 * Convenience function that computes SHA1 hash for a single data buffer.
 * 
 * @param data Input data to hash
 * @param data_size Size of input data
 * @param digest Output buffer for 20-byte hash
 */
void compute_sha1_checksum(const void *data, size_t data_size, uint8_t *digest) {
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)data, data_size);
    sha1_final(&ctx, digest);
}

/**
 * @brief Compares two SHA1 digests for equality
 * 
 * @param digest1 First SHA1 digest to compare
 * @param digest2 Second SHA1 digest to compare
 * @return 1 if digests are identical, 0 otherwise
 */
int compare_sha1_digests(const uint8_t *digest1, const uint8_t *digest2) {
    return memcmp(digest1, digest2, 20) == 0;
}

/**
 * @brief Converts SHA1 digest to hexadecimal string
 * 
 * @param digest 20-byte SHA1 digest
 * @param output Output buffer for hex string (minimum 41 bytes)
 * @param output_size Size of output buffer
 */
void sha1_to_hex_string(const uint8_t *digest, char *output, size_t output_size) {
    if (output_size < 41) return; // Need 40 chars + null terminator
    
    // Convert each byte to two hex characters
    for (int i = 0; i < 20; i++) {
        snprintf(output + i * 2, 3, "%02x", digest[i]);
    }
    output[40] = '\0';
}