#include "file_utils.h"
#include "registry_manager.h"
#include "config_manager.h"

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
    
    // Configurable output directories
    int template_count = 0;
    const char** directory_templates = get_output_directory_templates(&template_count);
    
    // Try each directory template until we find a writable one
    for (int i = 0; i < template_count; i++) {
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
 * @brief Checks if filename matches the exact DEX dump pattern
 * 
 * Pattern: dex_%d_%p_%s.dex
 * Where: 
 *   %d = region index (number)
 *   %p = memory address (pointer format) 
 *   %s = timestamp (YYYYMMDD_HHMMSS)
 * 
 * @param filename Filename to check
 * @return 1 if matches pattern, 0 otherwise
 */
int matches_dex_dump_pattern(const char* filename) {
    // Pattern breakdown:
    // "dex_" + number + "_" + pointer + "_" + timestamp + ".dex"
    
    // Check prefix
    if (strncmp(filename, "dex_", 4) != 0) {
        return 0;
    }
    
    // Find first underscore after "dex_"
    char* first_underscore = strchr(filename + 4, '_');
    if (!first_underscore) {
        return 0;
    }
    
    // Check if part between "dex_" and first underscore is a valid number
    char number_part[32];
    size_t num_len = first_underscore - (filename + 4);
    if (num_len == 0 || num_len >= sizeof(number_part)) {
        return 0;
    }
    
    strncpy(number_part, filename + 4, num_len);
    number_part[num_len] = '\0';
    
    // Verify it's a valid integer
    char* endptr;
    long region_index = strtol(number_part, &endptr, 10);
    if (endptr != number_part + num_len || region_index < 0) {
        return 0;
    }
    
    // Find second underscore (after pointer)
    char* second_underscore = strchr(first_underscore + 1, '_');
    if (!second_underscore) {
        return 0;
    }
    
    // Check if part between underscores looks like a pointer (contains 'x' for hex)
    int has_pointer_format = 0;
    for (char* p = first_underscore + 1; p < second_underscore; p++) {
        if (*p == 'x' || *p == 'X') {
            has_pointer_format = 1;
            break;
        }
    }
    
    if (!has_pointer_format) {
        return 0;
    }
    
    // Check for ".dex" extension
    char* dot_dex = strstr(second_underscore, ".dex");
    if (!dot_dex || strlen(dot_dex) != 4) {
        return 0;
    }
    
    // Verify timestamp part between second_underscore and .dex
    // Timestamp should be in format YYYYMMDD_HHMMSS (digits and underscore)
    char* timestamp_part = second_underscore + 1;
    size_t timestamp_len = dot_dex - timestamp_part;
    if (timestamp_len == 0) {
        return 0;
    }
    
    for (size_t i = 0; i < timestamp_len; i++) {
        if (!isdigit(timestamp_part[i]) && timestamp_part[i] != '_') {
            return 0;
        }
    }
    
    return 1; // All checks passed
}

/**
 * @brief Cleans the output directory by removing only DEX dump files matching the specific pattern
 * 
 * This function safely cleans the output directory by selectively deleting only files that match
 * the exact DEX dump filename pattern: "dex_%d_%p_%s.dex"
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

        char* filename = directory_entry->d_name;
        
        // Filter files: only delete those matching DEX dump pattern "dex_%d_%p_%s.dex"
        if (!matches_dex_dump_pattern(filename)) {
            VLOGD("Skipping non-DEX-dump file: %s", filename);
            continue; // Skip files that don't match exact pattern
        }

        char full_file_path[MAX_PATH_LENGTH];
        snprintf(full_file_path, sizeof(full_file_path), "%s/%s", 
                 directory_path, filename);
        
        // Delete only matching DEX dump files
        if (unlink(full_file_path) == 0) {
            deleted_file_count++;
            VLOGD("Deleted DEX dump file: %s", filename);
        } else {
            LOGE("Failed to delete file: %s", full_file_path);
            success_flag = 0;
        }
    }

    closedir(directory_handle);
    LOGI("Cleaned %d DEX dump files from directory: %s", deleted_file_count, directory_path);
    return success_flag;
}

/**
 * @brief Dumps memory content to a file with duplicate or exclude detection
 * 
 * This is the core function that writes detected DEX files to disk
 * after performing validation and duplicate or exclude checking.
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
    
    // Check if the dumped file is listed in the exclude list
    if (is_sha1_excluded(sha1_digest)) {
        VLOGD("Skipping excluded DEX file based on SHA1 checksum");
        return 0;
    }
    
    // Check if we've already dumped a file with this checksum
    if (is_checksum_already_dumped(sha1_digest)) {
        VLOGD("Skipping duplicate DEX file based on SHA1 checksum");
        return 0;
    }
    
    // Check if SHA1 already exists in any file in output directory (persistent duplicate detection)
    if (is_sha1_duplicate_in_directory(output_directory, sha1_digest)) {
        VLOGD("Skipping duplicate DEX file based on directory SHA1 check");
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