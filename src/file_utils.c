#include "file_utils.h"
#include "registry_manager.h"

/**
 * @brief Gets the current Android application's package name
 * 
 * Reads /proc/self/cmdline to determine the package name of the current process.
 * This is used to create package-specific output directories.
 * 
 * @return Constant pointer to package name string
 */
const char* get_current_package_name() {
    static char package_name[MAX_PACKAGE_NAME_LENGTH] = {0};
    
    // Read process command line to get package name
    FILE* command_file = fopen("/proc/self/cmdline", "r");
    
    if (command_file) {
        size_t bytes_read = fread(package_name, 1, sizeof(package_name) - 1, command_file);
        package_name[bytes_read] = '\0';
        fclose(command_file);
    }
    
    // Remove any process suffix (like :background)
    char* colon_position = strchr(package_name, ':');
    if (colon_position) *colon_position = 0;
    
    return package_name;
}

/**
 * @brief Creates directory hierarchy recursively
 * 
 * Given a path like "/a/b/c/d", this function creates all directories
 * in the path that don't already exist.
 * 
 * @param directory_path Full directory path to create
 */
void create_directory_hierarchy(const char* directory_path) {
    if (directory_path == NULL || strlen(directory_path) == 0) {
        LOGE("Invalid directory path provided");
        return;
    }
    
    char temporary_path[MAX_PATH_LENGTH];
    size_t path_length = strnlen(directory_path, MAX_PATH_LENGTH - 1);
    
    // Check for path length overflow
    if (path_length >= MAX_PATH_LENGTH - 1) {
        LOGE("Directory path exceeds maximum length: %s", directory_path);
        return;
    }
    
    // Copy path to temporary buffer for manipulation
    memcpy(temporary_path, directory_path, path_length);
    temporary_path[path_length] = '\0';
    
    // Create each directory in the path hierarchy
    for (char* path_ptr = temporary_path + 1; *path_ptr && path_ptr < temporary_path + MAX_PATH_LENGTH - 1; path_ptr++) {
        if (*path_ptr == '/') {
            *path_ptr = 0;          // Temporarily truncate at current segment
            mkdir(temporary_path, 0755); // Create directory
            *path_ptr = '/';        // Restore slash
        }
    }
    
    // Create the final directory
    if (strlen(temporary_path) > 0) {
        mkdir(temporary_path, 0755);
    }
}

/**
 * @brief Determines the best output directory for dumped files
 * 
 * Tries multiple common Android directories to find one that is writable.
 * Falls back to package's data directory if no external storage available.
 * 
 * @return Path to writable output directory
 */
char* get_output_directory_path() {
    static char output_directory[MAX_PATH_LENGTH];
    const char* package_name = get_current_package_name();
    
    // List of potential output directories in order of preference
    const char* directory_templates[] = OUTPUT_DIRECTORY_TEMPLATES;
    
    size_t template_count = sizeof(directory_templates) / sizeof(directory_templates[0]);
    
    // Try each directory template until we find a writable one
    for (size_t i = 0; i < template_count; i++) {
        snprintf(output_directory, sizeof(output_directory), 
                directory_templates[i], package_name);
        create_directory_hierarchy(output_directory);
        
        // Test if we can actually write to this directory
        char test_file_path[MAX_PATH_LENGTH];
        snprintf(test_file_path, sizeof(test_file_path), "%s/test_write", output_directory);
        FILE* test_file = fopen(test_file_path, "w");
        
        if (test_file) {
            fclose(test_file);
            remove(test_file_path); // Clean up test file
            LOGI("Selected output directory: %s", output_directory);
            return output_directory;
        }
    }
    
    // Fallback to first option even if not writable (will fail later)
    snprintf(output_directory, sizeof(output_directory), directory_templates[0], package_name);
    create_directory_hierarchy(output_directory);
    LOGI("Using fallback output directory: %s", output_directory);
    return output_directory;
}

/**
 * @brief Generates a unique filename for dumped DEX files
 * 
 * Creates filenames with timestamp and memory address to avoid collisions
 * and provide debugging information.
 * 
 * @param filename_buffer Output buffer for generated filename
 * @param buffer_size Size of output buffer
 * @param base_directory Base output directory path
 * @param region_index Index of memory region for naming
 * @param memory_address Memory address where DEX was found (for debugging)
 */
void generate_dump_filename(char* filename_buffer, size_t buffer_size, 
                           const char* base_directory, int region_index, 
                           void* memory_address) {
    time_t current_time = time(NULL);
    struct tm* time_info = localtime(&current_time);
    char timestamp_string[20];
    
    // Format timestamp as YYYYMMDD_HHMMSS
    strftime(timestamp_string, sizeof(timestamp_string), "%Y%m%d_%H%M%S", time_info);
    
    // Create filename: dex_{region_index}_{memory_address}_{timestamp}.dex
    snprintf(filename_buffer, buffer_size, "%s/dex_%d_%p_%s.dex", 
             base_directory, region_index, memory_address, timestamp_string);
}

/**
 * @brief Cleans the output directory by removing all existing files
 * 
 * This prevents accumulation of dumped files across multiple runs
 * and helps avoid storage issues.
 * 
 * @param directory_path Path to directory to clean
 * @return 1 if successful, 0 if errors occurred
 */
int clean_output_directory(const char* directory_path) {
    DIR* directory_handle = opendir(directory_path);
    if (!directory_handle) {
        // Directory doesn't exist is not an error
        if (errno == ENOENT) return 1;
        LOGE("Failed to open output directory: %s", directory_path);
        return 0;
    }

    struct dirent* directory_entry;
    int success_flag = 1;
    int deleted_file_count = 0;
    
    // Iterate through all directory entries
    while ((directory_entry = readdir(directory_handle)) != NULL) {
        // Skip . and .. entries
        if (strcmp(directory_entry->d_name, ".") == 0 || 
            strcmp(directory_entry->d_name, "..") == 0) continue;

        char full_file_path[MAX_PATH_LENGTH];
        snprintf(full_file_path, sizeof(full_file_path), "%s/%s", 
                 directory_path, directory_entry->d_name);
        
        // Delete the file
        if (unlink(full_file_path) == 0) {
            deleted_file_count++;
        } else {
            LOGE("Failed to delete file: %s", full_file_path);
            success_flag = 0;
        }
    }

    closedir(directory_handle);
    LOGI("Cleaned %d files from directory: %s", deleted_file_count, directory_path);
    return success_flag;
}

/**
 * @brief Dumps memory content to a file with duplicate detection
 * 
 * This is the core function that writes detected DEX files to disk
 * after performing validation and duplicate checking.
 * 
 * @param output_directory Directory to write the file to
 * @param memory_region Memory region information for tracking
 * @param region_index Index of the region for filename
 * @param data_buffer Pointer to DEX file data in memory
 * @param data_size Size of DEX file data
 * @return 1 if successfully dumped, 0 on failure
 */
int dump_memory_to_file(const char* output_directory, const MemoryRegion* memory_region, 
                       int region_index, const void* data_buffer, size_t data_size) {
    // Check if we've already dumped this file (by inode)
    if (memory_region->inode_number != 0 && 
        is_file_already_dumped(memory_region->inode_number)) {
        VLOGD("Skipping already dumped region with inode: %lu", memory_region->inode_number);
        return 0;
    }
    
    // Validate DEX file size constraints
    if (data_size < DEX_MIN_FILE_SIZE || data_size > DEX_MAX_FILE_SIZE) {
        LOGW("Invalid DEX file size: %zu bytes, skipping dump", data_size);
        return 0;
    }
    
    // Compute SHA1 checksum for duplicate detection
    uint8_t sha1_digest[20];
    compute_sha1_checksum(data_buffer, data_size, sha1_digest);
    
    // Check if we've already dumped a file with this checksum
    if (is_checksum_already_dumped(sha1_digest)) {
        VLOGD("Skipping duplicate DEX file based on SHA1 checksum");
        return 0;
    }
    
    // Generate unique output filename
    char output_file_path[MAX_PATH_LENGTH];
    generate_dump_filename(output_file_path, sizeof(output_file_path), 
                          output_directory, region_index, memory_region->start_address);
    
    // Write data to file
    FILE* output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        LOGE("Failed to create output file %s: %s", output_file_path, strerror(errno));
        return 0;
    }
    
    size_t bytes_written = fwrite(data_buffer, 1, data_size, output_file);
    fclose(output_file);
    
    // Verify complete write
    if (bytes_written != data_size) {
        LOGE("Incomplete write to file %s", output_file_path);
        remove(output_file_path); // Clean up partial file
        return 0;
    }
    
    // Register the dumped file to prevent future duplicates
    if (memory_region->inode_number != 0) {
        register_dumped_file_with_checksum(memory_region->inode_number, output_file_path, sha1_digest);
    } else {
        register_dumped_file_with_checksum(0, output_file_path, sha1_digest);
    }
    
    // Log success with partial SHA1 for identification
    char sha1_partial[9];
    snprintf(sha1_partial, sizeof(sha1_partial), "%02x%02x%02x%02x", 
             sha1_digest[0], sha1_digest[1], sha1_digest[2], sha1_digest[3]);
    
    LOGI("Successfully dumped %zu bytes to %s (SHA1: %s...)", 
         data_size, output_file_path, sha1_partial);
    return 1;
}