#include "dex_detector.h"

/**
 * @brief Validates the structure of a potential DEX header
 * 
 * This function performs comprehensive validation of DEX header fields
 * to distinguish real DEX files from random memory that matches the magic.
 * 
 * @param header_start Pointer to the start of memory buffer to check
 * @param buffer_size Total size of the memory buffer
 * @param header_offset Offset within buffer where header is suspected
 * @return 1 if header is valid, 0 otherwise
 */
int validate_dex_header_structure(const void* header_start, size_t buffer_size, 
                                 size_t header_offset) {
    // Basic bounds checking
    if (header_offset + DEX_HEADER_SIZE > buffer_size) return 0;

    uint32_t dex_file_size = 0;
    // Safely read the file size field from DEX header (offset 0x20)
    if (!read_memory_safely((const char*)header_start + header_offset + 0x20, 
                           &dex_file_size, sizeof(uint32_t))) {
        return 0;
    }

    // Validate DEX file size constraints
    if (dex_file_size < DEX_MIN_FILE_SIZE || dex_file_size > DEX_MAX_FILE_SIZE) {
        LOGW("Invalid DEX file size in header: %u (expected %d-%d)", 
             dex_file_size, DEX_MIN_FILE_SIZE, DEX_MAX_FILE_SIZE);
        return 0;
    }

    // Ensure claimed size fits in available buffer
    if (dex_file_size > (buffer_size - header_offset)) {
        LOGW("DEX file size %u exceeds available buffer space %zu", 
             dex_file_size, buffer_size - header_offset);
        return 0;
    }

    // Verify header size field (should be 0x70 for standard DEX)
    uint32_t header_size_value = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x24, 
                           &header_size_value, sizeof(uint32_t))) {
        return 0;
    }
    
    if (header_size_value != DEX_HEADER_SIZE) {
        LOGW("DEX header size mismatch: %u (expected %u)", 
             header_size_value, DEX_HEADER_SIZE);
        return 0;
    }

    // Check endian tag (should be 0x12345678 for standard DEX)
    uint32_t endian_tag_value = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x28, 
                           &endian_tag_value, sizeof(uint32_t))) {
        return 0;
    }
    
    if (endian_tag_value != 0x12345678U) {
        LOGW("Unexpected DEX endian tag: 0x%08x", endian_tag_value);
        return 0;
    }

    // Validate string table references (common attack vector)
    uint32_t string_table_size = 0, string_table_offset = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x38, 
                           &string_table_size, sizeof(uint32_t))) return 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x3C, 
                           &string_table_offset, sizeof(uint32_t))) return 0;
    
    // Ensure string table references are within file bounds
    if (string_table_offset > dex_file_size) return 0;
    if ((uint64_t)string_table_offset + (uint64_t)string_table_size * 4 > dex_file_size) return 0;

    return 1; // All validation passed
}

/**
 * @brief Scans memory for DEX file signatures
 * 
 * This function searches through memory for DEX magic bytes and
 * validates any potential matches. It handles multiple DEX versions.
 * 
 * @param scan_start Starting address to scan from
 * @param scan_size Size of memory region to scan
 * @param max_scan_limit Maximum bytes to scan (for performance)
 * @param detection_result Output parameter for detection results
 * @return 1 if DEX found, 0 otherwise
 */
int scan_for_dex_signature(const void* scan_start, size_t scan_size, 
                          size_t max_scan_limit, DexDetectionResult* detection_result) {
    // Sanity check inputs
    if (scan_start == NULL || scan_size == 0) return 0;
    
    // Calculate actual scanning limit
    size_t actual_scan_limit = (max_scan_limit > scan_size) ? scan_size : max_scan_limit;
    if (actual_scan_limit < 8) return 0; // Need at least 8 bytes for signature
    
    unsigned char signature_buffer[8]; // Buffer to read potential signatures
    
    // Scan through memory in 4-byte increments
    for (size_t current_offset = 0; current_offset <= actual_scan_limit - 8; current_offset += 4) {
        // Safely read 8 bytes to check for signature
        if (!read_memory_safely((const char*)scan_start + current_offset, 
                               signature_buffer, 8)) {
            continue; // Skip if we can't read this location
        }
        
        // Check for DEX signatures with various versions (035-039)
        if (memcmp(signature_buffer, "dex\n035", 7) == 0 || 
            memcmp(signature_buffer, "dex\n036", 7) == 0 ||
            memcmp(signature_buffer, "dex\n037", 7) == 0 ||
            memcmp(signature_buffer, "dex\n038", 7) == 0 ||
            memcmp(signature_buffer, "dex\n039", 7) == 0) {
            
            VLOGD("Detected DEX signature at offset %zu", current_offset);
            
            // Validate the header to confirm it's a real DEX file
            if (validate_dex_header_structure(scan_start, scan_size, current_offset)) {
                uint32_t file_size_value = 0;
                // Read the actual file size from validated header
                if (read_memory_safely((const char*)scan_start + current_offset + 0x20, 
                                      &file_size_value, sizeof(uint32_t))) {
                    detection_result->dex_size = file_size_value;
                    detection_result->dex_address = (void*)((char*)scan_start + current_offset);
                    LOGI("Valid DEX file detected at %p, size: %u bytes", 
                         detection_result->dex_address, file_size_value);
                    return 1; // Successfully found and validated DEX
                }
            } else {
                LOGW("DEX signature found but header validation failed at offset %zu", 
                     current_offset);
            }
        }
    }
    return 0; // No valid DEX found
}

/**
 * @brief Scans a memory region for standard DEX files
 * 
 * Wrapper function that applies size checks before scanning.
 * 
 * @param region_start Start of memory region to scan
 * @param region_size Size of memory region
 * @param detection_result Output for detection results
 * @return 1 if DEX found, 0 otherwise
 */
int scan_region_for_dex_files(const void* region_start, size_t region_size, 
                             DexDetectionResult* detection_result) {
    // Skip regions too small to contain a DEX header
    if (region_size < DEX_HEADER_SIZE) return 0;
    
    // Apply scanning limit to large regions for performance
    size_t scan_limit = (region_size > DEFAULT_SCAN_LIMIT) ? DEFAULT_SCAN_LIMIT : region_size;
    return scan_for_dex_signature(region_start, region_size, scan_limit, detection_result);
}

/**
 * @brief Scans OAT containers for embedded DEX files
 * 
 * OAT files are Android's optimized ART format that often contain
 * embedded DEX files. This function specifically handles OAT containers.
 * 
 * @param region_start Start of memory region
 * @param region_size Size of memory region  
 * @param detection_result Output for detection results
 * @return 1 if DEX found in OAT, 0 otherwise
 */
int scan_region_for_oat_dex_files(const void* region_start, size_t region_size, 
                                 DexDetectionResult* detection_result) {
    // Check for OAT magic signature
    if (region_size < 8) return 0;
    
    unsigned char oat_magic[4];
    if (!read_memory_safely(region_start, oat_magic, 4)) return 0;
    
    // Verify OAT container signature
    if (memcmp(oat_magic, "oat\n", 4) != 0) return 0;
    
    VLOGD("Detected OAT container, scanning for embedded DEX");
    // Scan first 64KB of OAT for embedded DEX (common location)
    return scan_for_dex_signature(region_start, region_size, 64 * 1024, detection_result);
}

/**
 * @brief Performs comprehensive DEX detection using multiple strategies
 * 
 * This function tries different detection methods to find DEX files
 * in various formats and containers.
 * 
 * @param region_start Start of memory region to scan
 * @param region_size Size of memory region
 * @param detection_result Output for detection results
 * @return 1 if DEX found, 0 otherwise
 */
int perform_comprehensive_dex_detection(const void* region_start, size_t region_size, 
                                       DexDetectionResult* detection_result) {
    // Array of detection strategies to try
    const struct {
        const char* detection_type;  // Name for logging
        int (*detector_function)(const void*, size_t, DexDetectionResult*); // Function pointer
    } detection_strategies[] = {
        {"standard DEX", scan_region_for_dex_files},    // First try standard DEX
        {"OAT container", scan_region_for_oat_dex_files} // Then try OAT containers
    };
    
    size_t strategy_count = sizeof(detection_strategies) / sizeof(detection_strategies[0]);
    
    // Try each detection strategy in order
    for (size_t i = 0; i < strategy_count; i++) {
        VLOGD("Attempting %s detection", detection_strategies[i].detection_type);
        if (detection_strategies[i].detector_function(region_start, region_size, detection_result)) {
            LOGI("DEX file detected via %s strategy", detection_strategies[i].detection_type);
            return 1; // Success with this strategy
        }
    }
    
    return 0; // No strategies succeeded
}