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