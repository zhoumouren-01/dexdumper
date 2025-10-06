#ifndef DEXDUMPER_MEMORY_SCANNER_H
#define DEXDUMPER_MEMORY_SCANNER_H

// Memory scanner header - declares memory region analysis and scanning functions

#include "common.h"
#include "config.h"
#include "signal_handler.h"  // For safe memory access

/**
 * Memory Scanning Functions:
 * 
 * These functions handle parsing process memory maps, filtering relevant regions,
 * and creating safe copies of memory for analysis.
 */

// Parses /proc/self/maps to get memory region information
int parse_memory_regions(MemoryRegion** regions_array);

// Determines if a memory region should be scanned for DEX files
int should_scan_memory_region(const MemoryRegion* memory_region);

// Tests if a memory region can be safely read
int test_region_read_access(const MemoryRegion* memory_region);

// Identifies high-potential regions likely to contain DEX files
int is_potential_dex_region(const MemoryRegion* memory_region);

// Creates safe copy of memory for processing and dumping
void* create_memory_copy(const void* source_address, size_t copy_size);

#endif