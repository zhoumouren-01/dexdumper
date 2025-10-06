#ifndef DEXDUMPER_DEX_DETECTOR_H
#define DEXDUMPER_DEX_DETECTOR_H

// DEX detection header - declares functions for finding DEX files in memory

#include "common.h"
#include "config.h"
#include "signal_handler.h"  // For read_memory_safely

/**
 * DEX Detection Functions:
 * 
 * These functions implement the core logic for identifying DEX files
 * in process memory using signature scanning and header validation.
 */

// Validates DEX header structure to confirm genuine DEX files
int validate_dex_header_structure(const void* header_start, size_t buffer_size, 
                                 size_t header_offset);

// Scans memory region for DEX magic signatures
int scan_for_dex_signature(const void* scan_start, size_t scan_size, 
                          size_t max_scan_limit, DexDetectionResult* detection_result);

// Scans a memory region for standard DEX files
int scan_region_for_dex_files(const void* region_start, size_t region_size, 
                             DexDetectionResult* detection_result);

// Specialized scanner for OAT files containing embedded DEX
int scan_region_for_oat_dex_files(const void* region_start, size_t region_size, 
                                 DexDetectionResult* detection_result);

// Comprehensive detection using multiple strategies
int perform_comprehensive_dex_detection(const void* region_start, size_t region_size, 
                                       DexDetectionResult* detection_result);

#endif