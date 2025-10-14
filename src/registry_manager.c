#include "registry_manager.h"

// Global registry state - tracks all dumped files to prevent duplicates
DumpedFileInfo* dumped_files_registry = NULL;
int dumped_files_count = 0;
int dumped_files_capacity = 0;
pthread_mutex_t dump_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Checks if a file has already been dumped based on inode number
 * 
 * Uses the file's inode number (unique filesystem identifier) to track
 * whether we've already processed this file, preventing redundant dumping.
 * 
 * @param file_inode Inode number to check
 * @return 1 if already dumped, 0 if new file
 */
int is_file_already_dumped(ino_t file_inode) {
    pthread_mutex_lock(&dump_registry_mutex);
    
    // Linear search through registry (typically small)
    for (int i = 0; i < dumped_files_count; i++) {
        if (dumped_files_registry[i].inode_number == file_inode) {
            pthread_mutex_unlock(&dump_registry_mutex);
            return 1; // Found duplicate
        }
    }
    
    pthread_mutex_unlock(&dump_registry_mutex);
    return 0; // New file
}

/**
 * @brief Checks if content has been dumped based on SHA1 checksum
 * 
 * Uses cryptographic hash to detect duplicate content even if files
 * have different inodes (copied files, same content in different locations).
 * 
 * @param sha1_digest 20-byte SHA1 hash to check
 * @return 1 if duplicate content found, 0 if new content
 */
int is_checksum_already_dumped(const uint8_t *sha1_digest) {
    pthread_mutex_lock(&dump_registry_mutex);
    
    // Search for matching SHA1 digest
    for (int i = 0; i < dumped_files_count; i++) {
        if (compare_sha1_digests(dumped_files_registry[i].sha1_digest, sha1_digest)) {
            pthread_mutex_unlock(&dump_registry_mutex);
            VLOGD("Duplicate DEX file detected by SHA1 checksum");
            return 1; // Duplicate content found
        }
    }
    
    pthread_mutex_unlock(&dump_registry_mutex);
    return 0; // New content
}

/**
 * @brief Registers a dumped file in the global registry
 * 
 * Adds file metadata to the registry to prevent future duplicates.
 * Implements circular buffer behavior when maximum capacity is reached.
 * 
 * @param file_inode Inode number of dumped file (0 if unknown)
 * @param file_path File path where content was saved
 * @param sha1_digest 20-byte SHA1 hash of file content
 */
void register_dumped_file_with_checksum(ino_t file_inode, const char* file_path, 
                                      const uint8_t *sha1_digest) {
    pthread_mutex_lock(&dump_registry_mutex);
    
    // Handle registry capacity limits
    if (dumped_files_count >= MAX_DUMPED_FILES) {
        // Remove oldest entry to make space (circular buffer behavior)
        memmove(&dumped_files_registry[0], &dumped_files_registry[1],
                (MAX_DUMPED_FILES - 1) * sizeof(DumpedFileInfo));
        dumped_files_count = MAX_DUMPED_FILES - 1;
        LOGD("Dumped files registry rotated, oldest entry removed");
    }
    
    // Expand registry capacity if needed
    if (dumped_files_capacity < MAX_DUMPED_FILES) {
        void *new_memory = realloc(dumped_files_registry, 
                                  MAX_DUMPED_FILES * sizeof(DumpedFileInfo));
        if (new_memory) {
            dumped_files_registry = new_memory;
            dumped_files_capacity = MAX_DUMPED_FILES;
            LOGD("Dumped files registry capacity expanded to %d", MAX_DUMPED_FILES);
        } else {
            LOGE("Memory reallocation failed for dumped files registry");
            pthread_mutex_unlock(&dump_registry_mutex);
            return;
        }
    }
    
    // Add new entry to registry
    dumped_files_registry[dumped_files_count].inode_number = file_inode;
    dumped_files_registry[dumped_files_count].dump_timestamp = time(NULL);
    
    // Safe string copy for file path
    strncpy(dumped_files_registry[dumped_files_count].file_path, file_path, 
            sizeof(dumped_files_registry[0].file_path) - 1);
    dumped_files_registry[dumped_files_count].file_path[sizeof(dumped_files_registry[0].file_path) - 1] = '\0';
    
    // Copy SHA1 digest
    memcpy(dumped_files_registry[dumped_files_count].sha1_digest, sha1_digest, 20);
    dumped_files_count++;
    
    // Log registration for debugging
    char sha1_hex[41];
    sha1_to_hex_string(sha1_digest, sha1_hex, sizeof(sha1_hex));
    VLOGD("Registered dumped file: inode %lu, SHA1: %s, total count: %d", 
          file_inode, sha1_hex, dumped_files_count);
    
    pthread_mutex_unlock(&dump_registry_mutex);
}

/**
 * @brief Checks if a SHA1 digest is in the exclusion list
 * 
 * @param sha1_digest 20-byte SHA1 digest to check
 * @return 1 if excluded, 0 if not found in exclusion list
 */
int is_sha1_excluded(const uint8_t* sha1_digest) {
    // Convert input SHA1 to hex string
    char input_sha1_hex[41];
    sha1_to_hex_string(sha1_digest, input_sha1_hex, sizeof(input_sha1_hex));
    
    // Get exclusion list from config
    const char* excluded_sha1_hex[] = EXCLUDED_SHA1_LIST;
    int excluded_count = sizeof(excluded_sha1_hex) / sizeof(excluded_sha1_hex[0]);
    
    if (excluded_count == 0) {
        LOGI("SHA1 exclusion list is empty");
        return 0; // No exclusion list or empty list
    }
    
    // Compare with each excluded SHA1
    for (int i = 0; i < excluded_count; i++) {
        if (strcasecmp(input_sha1_hex, excluded_sha1_hex[i]) == 0) {
            char partial_sha1[9];
            snprintf(partial_sha1, sizeof(partial_sha1), "%.8s", input_sha1_hex);
            LOGI("Skipping excluded DEX (SHA1: %s...)", partial_sha1);
            return 1; // Found in exclusion list
        }
    }
    return 0; // Not found in exclusion list
}

/**
 * @brief Checks if a DEX file with the same SHA1 already exists in the output directory
 * 
 * This function scans through all files in the output directory to find duplicate DEX files.
 * This prevents unnecessary SHA1 computation for non-DEX files and large files.
 * 
 * @param output_directory Path to the directory where DEX files are stored
 * @param sha1_digest The 20-byte SHA1 hash of the DEX file we want to check
 * @return 1 if a duplicate file is found, 0 if the file is unique
 */
int is_sha1_duplicate_in_directory(const char* output_directory, const uint8_t* sha1_digest) {
    // Try to open the output directory
    DIR* directory_handle = opendir(output_directory);
    if (!directory_handle) {
        // If directory doesn't exist, there are no duplicates
        if (errno == ENOENT) return 0;
        LOGE("Failed to open directory for duplicate check: %s", output_directory);
        return 0;
    }

    struct dirent* directory_entry;
    int duplicate_found = 0;
    
    // Convert the binary SHA1 to readable hex string for logging
    char input_sha1_hex[41];
    sha1_to_hex_string(sha1_digest, input_sha1_hex, sizeof(input_sha1_hex));
    
    // Buffer to read and check DEX file header
    uint8_t dex_header[DEX_HEADER_SIZE];
    
    // Loop through each file in the directory
    while ((directory_entry = readdir(directory_handle)) != NULL && !duplicate_found) {
        // Skip the special directory entries "." and ".."
        if (strcmp(directory_entry->d_name, ".") == 0 || 
            strcmp(directory_entry->d_name, "..") == 0) continue;

        char* filename = directory_entry->d_name;
        
        // QUICK FILTER: Only process files with ".dex" extension
        // Check if filename ends with exactly ".dex" (4 characters)
        char* dot_dex = strstr(filename, ".dex");
        if (!dot_dex || strlen(dot_dex) != 4) {
            continue; // Skip non-DEX files
        }

        // Build the full path to the file
        char full_file_path[MAX_PATH_LENGTH];
        snprintf(full_file_path, sizeof(full_file_path), "%s/%s", 
                 output_directory, filename);

        // Get file information to check if it's a regular file (not directory)
        struct stat file_stat;
        if (stat(full_file_path, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
            continue; // Skip if we can't get file info or it's not a regular file
        }

        // SIZE CHECK: Skip files that are too small or too large to be DEX files
        if (file_stat.st_size > DEX_MAX_FILE_SIZE || file_stat.st_size < DEX_MIN_FILE_SIZE) {
            continue;
        }

        // Open the file for reading
        FILE* file = fopen(full_file_path, "rb");
        if (!file) {
            VLOGD("Cannot open file for reading: %s", full_file_path);
            continue;
        }

        // STEP 1: QUICK DEX HEADER VALIDATION
        // Read the first few bytes to check DEX magic signature
        if (fread(dex_header, 1, DEX_HEADER_SIZE, file) != DEX_HEADER_SIZE) {
            fclose(file);
            continue; // File is too small or can't be read
        }

        // Check if the file has the correct DEX magic bytes at the beginning
        if (memcmp(dex_header, "dex\n", 4) != 0) {
            fclose(file);
            continue; // Not a valid DEX file, skip SHA1 computation
        }

        // STEP 2: MEMORY-EFFICIENT SHA1 COMPUTATION
        // Reset file pointer to beginning for SHA1 computation
        fseek(file, 0, SEEK_SET);
        
        // Initialize SHA1 context for computing hash
        sha1_context sha1_ctx;
        sha1_init(&sha1_ctx);
        
        // Use a buffer to read file in chunks (memory efficient)
        uint8_t buffer[8192]; // 8KB buffer - balances memory usage and I/O efficiency
        size_t bytes_read;
        
        // Read file in chunks and update SHA1 computation
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            sha1_update(&sha1_ctx, buffer, bytes_read);
        }
        fclose(file);
        
        // Finalize SHA1 computation to get the hash
        uint8_t file_sha1[20];
        sha1_final(&sha1_ctx, file_sha1);
        
        // STEP 3: DUPLICATE CHECK
        // Compare the computed SHA1 with the input SHA1
        if (compare_sha1_digests(sha1_digest, file_sha1)) {
            // Found a duplicate! Log it and stop searching
            char partial_sha1[9];
            snprintf(partial_sha1, sizeof(partial_sha1), "%.8s", input_sha1_hex);
            LOGI("Duplicate DEX file found! SHA1: %s... already saved as: %s", 
                 partial_sha1, filename);
            duplicate_found = 1;
        }
    }

    // Clean up - close the directory
    closedir(directory_handle);
    return duplicate_found;
}