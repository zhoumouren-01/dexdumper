#ifndef DEXDUMPER_REGISTRY_MANAGER_H
#define DEXDUMPER_REGISTRY_MANAGER_H

// Registry manager header - declares duplicate tracking system

#include "common.h"
#include "config.h"
#include "sha1.h"  // For checksum functions

/**
 * Duplicate Prevention System:
 * 
 * These functions maintain a registry of dumped files to prevent
 * redundant operations and manage memory usage.
 */

// Checks if file has been dumped by inode number
int is_file_already_dumped(ino_t file_inode);

// Checks if content has been dumped by SHA1 checksum  
int is_checksum_already_dumped(const uint8_t *sha1_digest);

// Registers newly dumped file in the global registry
void register_dumped_file_with_checksum(ino_t file_inode, const char* file_path, 
                                      const uint8_t *sha1_digest);

// Global registry variables (defined in registry_manager.c)
extern DumpedFileInfo* dumped_files_registry;  // Array of dumped file info
extern int dumped_files_count;                 // Current number of entries
extern int dumped_files_capacity;              // Maximum capacity of array
extern pthread_mutex_t dump_registry_mutex;    // Thread safety mutex

#endif