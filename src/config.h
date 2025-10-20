#ifndef DEXDUMPER_CONFIG_H
#define DEXDUMPER_CONFIG_H

// Configuration header - defines constants, macros and global settings
// Central place to tune the behavior of the dumper

// Android log tag for filtering logs
#define LOG_TAG "DexDumper"

// DEX file identification
#define DEX_MAGIC_SIGNATURE "dex\n"  // Magic bytes for DEX files
#define DEX_HEADER_SIZE 0x70         // Size of standard DEX header
#define DEX_MAGIC_LEN 8              // Length of magic signature

// File system limits
#define MAX_PATH_LENGTH 512          // Maximum file path length
#define MAX_REGION_NAME 256          // Maximum memory region name length
#define MAX_PACKAGE_NAME_LENGTH 256  // Maximum Android package name length

// Memory scanning limits
#define DEFAULT_SCAN_LIMIT (2 * 1024 * 1024) // 2MB default scan limit per region
#define MAX_REGION_SIZE (200 * 1024 * 1024)  // 200MB maximum region size to scan

// DEX file size validation
#define DEX_MIN_FILE_SIZE 1024               // 1KB minimum DEX size
#define DEX_MAX_FILE_SIZE (50 * 1024 * 1024) // 50MB maximum DEX size

// Registry and tracking
#define MAX_DUMPED_FILES 512                 // Maximum files to track
#define MAX_REGIONS_INITIAL_CAPACITY 100     // Initial memory regions array size

// Feature toggles
#define ENABLE_REGION_FILTERING 1    // Enable smart region filtering
#define ENABLE_SECOND_SCAN 0  // Enable/disable second scan

// Timing Configuration (in seconds)
#define THREAD_INITIAL_DELAY 8     // Initial delay before first scan
#define SECOND_SCAN_DELAY 12       // Delay between first and second scan

// Output Directory Configuration
#define OUTPUT_DIRECTORY_TEMPLATES { \
    "/data/data/%s/files/dex_dump", \
    "/data/user/0/%s/files/dex_dump", \
    "/storage/emulated/0/Android/data/%s/files/dex_dump", \
    "/sdcard/Android/data/%s/files/dex_dump" \
}

// SHA1 Exclusion List - Add SHA1 hashes of DEX files to exclude from dumping
#define EXCLUDED_SHA1_LIST { \
    "da39a3ee5e6b4b0d3255bfef95601890afd80709", /* Empty file SHA1 */ \
    "5ba93c9db0cff93f52b521d7420e43f6eda2784f", /* Null file 1 SHA1 */ \
    "1489f923c4dca729178b3e3233458550d8dddf29" /* Null file 2 SHA1 */ \
}

// Signal Handling
#define SIGNAL_STACK_SIZE SIGSTKSZ   // Size of signal handling stack

// Logging macros for different levels
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__) 
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Verbose logging - only logs when verbose_logging is enabled
#define VLOGD(...) do { if (verbose_logging) LOGD(__VA_ARGS__); } while (0)

// Global verbosity control
extern int verbose_logging;

#endif