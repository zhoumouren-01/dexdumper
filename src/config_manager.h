#ifndef DEXDUMPER_CONFIG_MANAGER_H
#define DEXDUMPER_CONFIG_MANAGER_H

#include "common.h"
#include "config.h"

// Initialize configuration management system
void init_config_manager(void);

// Cleanup configuration resources
void cleanup_config_manager(void);

// Check if second memory scan is enabled
int should_enable_second_scan(void);

// Check if region filtering is enabled
int should_enable_region_filtering(void);

// Get initial delay before first scan (seconds)
int get_initial_delay(void);

// Get delay between scans (seconds)
int get_second_scan_delay(void);

// Get output directory path templates
const char** get_output_directory_templates(int* count);

// Get list of excluded SHA1 hashes
const char** get_excluded_sha1_list(int* count);

#endif