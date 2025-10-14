#ifndef DEXDUMPER_FILE_UTILS_H
#define DEXDUMPER_FILE_UTILS_H

// File utilities header - declares file system operations and directory management

#include "common.h"
#include "config.h"
#include "registry_manager.h"  // For duplicates and excludes tracking
#include "sha1.h"              // For checksum computation

/**
 * File System Operations:
 * 
 * These functions handle all file I/O, directory creation, and path management
 * for the dumped DEX files.
 */

// Gets current Android application package name
const char* get_current_package_name(void);

// Creates directory hierarchy recursively
void create_directory_hierarchy(const char* directory_path);

// Determines optimal output directory for dumped files
char* get_output_directory_path(void);

// Helper function for pattern matching
int matches_dex_dump_pattern(const char* filename);

// Cleans output directory by removing existing files
int clean_output_directory(const char* directory_path);

// Generates unique filename for dumped DEX files
void generate_dump_filename(char* filename_buffer, size_t buffer_size, 
                           const char* base_directory, int region_index, 
                           void* memory_address);

// Core function to dump memory content to file with validation
int dump_memory_to_file(const char* output_directory, const MemoryRegion* memory_region, 
                       int region_index, const void* data_buffer, size_t data_size);

#endif