#include "signal_handler.h"

// Thread-local variables for signal handling recovery
__thread sigjmp_buf signal_recovery_buffer;
__thread volatile sig_atomic_t recovery_buffer_ready = 0;

// Global signal handling state
pthread_mutex_t signal_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
int signal_handlers_installed = 0;
stack_t signal_handler_stack = {0};

/**
 * @brief Signal handler for memory access violations
 * 
 * This function catches SIGSEGV (segmentation fault) and SIGBUS (bus error)
 * signals that occur when trying to read invalid memory. Instead of crashing,
 * it jumps back to the validation point using siglongjmp.
 * 
 * @param signal_number Signal that was caught (SIGSEGV or SIGBUS)
 */
static void memory_access_signal_handler(int signal_number) {
    // If recovery buffer is set up, jump back to safe point
    if (recovery_buffer_ready) {
        recovery_buffer_ready = 0;
        siglongjmp(signal_recovery_buffer, 1);
    } else {
        // If no recovery point, exit gracefully with signal code
        _exit(128 + signal_number);
    }
}

/**
 * @brief Installs signal handlers for safe memory access
 * 
 * Sets up signal handlers and alternate signal stack to catch and recover
 * from memory access violations during memory scanning.
 */
void install_memory_signal_handlers(void) {
    pthread_mutex_lock(&signal_handler_mutex);
    
    // Install handlers only once
    if (!signal_handlers_installed) {
        // Set up alternate stack for signal handling to avoid stack overflow
        if (signal_handler_stack.ss_sp == NULL) {
            signal_handler_stack.ss_sp = malloc(SIGNAL_STACK_SIZE);
            if (signal_handler_stack.ss_sp) {
                signal_handler_stack.ss_size = SIGNAL_STACK_SIZE;
                signal_handler_stack.ss_flags = 0;
                
                // Install alternate stack
                if (sigaltstack(&signal_handler_stack, NULL) == 0) {
                    LOGI("Alternate signal stack installed successfully (%ld bytes)", 
                         (long)SIGNAL_STACK_SIZE);
                } else {
                    LOGW("Failed to setup alternate signal stack: %s", strerror(errno));
                    free(signal_handler_stack.ss_sp);
                    signal_handler_stack.ss_sp = NULL;
                }
            } else {
                LOGW("Memory allocation failed for alternate signal stack");
            }
        }

        // Configure signal action structure
        struct sigaction signal_action;
        memset(&signal_action, 0, sizeof(signal_action));
        signal_action.sa_handler = memory_access_signal_handler;
        sigemptyset(&signal_action.sa_mask); // Don't block other signals
        
        // Use alternate stack if available
        if (signal_handler_stack.ss_sp) {
            signal_action.sa_flags = SA_RESTART | SA_ONSTACK;
            LOGI("Signal handlers configured with alternate stack");
        } else {
            signal_action.sa_flags = SA_RESTART;
            LOGW("Signal handlers using main stack (alternate unavailable)");
        }
        
        // Install SIGSEGV handler (segmentation faults)
        if (sigaction(SIGSEGV, &signal_action, NULL) == 0) {
            LOGI("SIGSEGV handler installed successfully");
        } else {
            LOGE("SIGSEGV handler installation failed: %s", strerror(errno));
        }
        
        // Install SIGBUS handler (bus errors - invalid memory access)
        if (sigaction(SIGBUS, &signal_action, NULL) == 0) {
            LOGI("SIGBUS handler installed successfully");
        } else {
            LOGE("SIGBUS handler installation failed: %s", strerror(errno));
        }
        
        signal_handlers_installed = 1;
    }
    
    pthread_mutex_unlock(&signal_handler_mutex);
}

/**
 * @brief Validates that memory range can be safely accessed
 * 
 * Uses signal handlers to test read access to memory without crashing.
 * This is essential for scanning unknown memory regions.
 * 
 * @param memory_address Starting address to validate
 * @param memory_size Number of bytes to validate
 * @return 1 if memory is readable, 0 if protected/invalid
 */
int validate_memory_access(const void* memory_address, size_t memory_size) {
    if (memory_address == NULL) return 0;
    
    uintptr_t address_value = (uintptr_t)memory_address;
    
    // Basic address sanity checks
    if (address_value < 0x1000 || address_value > (UINTPTR_MAX - memory_size)) {
        return 0;
    }
    
    // Set up recovery point for signal handler
    if (sigsetjmp(signal_recovery_buffer, 1) == 0) {
        recovery_buffer_ready = 1;
        
        // Test read access to first byte
        *((volatile char*)memory_address);
        
        // Test read access to last byte
        if (memory_size > 1) {
            *((volatile char*)((char*)memory_address + memory_size - 1));
        }
        
        recovery_buffer_ready = 0;
        return 1; // Memory is readable
    } else {
        // Signal handler jumped here - memory is not readable
        recovery_buffer_ready = 0;
        return 0;
    }
}

/**
 * @brief Safely reads memory with signal protection
 * 
 * Copies memory from source to destination with protection against
 * segmentation faults and bus errors. Essential for scanning unknown
 * memory regions safely.
 * 
 * @param source_address Address to read from
 * @param destination_buffer Buffer to read into
 * @param read_size Number of bytes to read
 * @return 1 if read successful, 0 if memory inaccessible
 */
int read_memory_safely(const void* source_address, void* destination_buffer, 
                      size_t read_size) {
    // Validate input parameters
    if (source_address == NULL || destination_buffer == NULL || read_size == 0) {
        return 0;
    }

    uintptr_t source_addr = (uintptr_t)source_address;
    if (source_addr < 0x1000) return 0; // Null page protection

    // First validate that we can access this memory range
    if (!validate_memory_access(source_address, read_size)) {
        VLOGD("Memory validation failed for address %p, size %zu", source_address, read_size);
        return 0;
    }

    // Ensure signal handlers are installed
    install_memory_signal_handlers();

    // Set up recovery point for the actual memory copy
    if (sigsetjmp(signal_recovery_buffer, 1) == 0) {
        recovery_buffer_ready = 1;
        
        // Attempt the memory copy - this may trigger SIGSEGV/SIGBUS
        memcpy(destination_buffer, source_address, read_size);
        
        recovery_buffer_ready = 0;
        return 1; // Success
    } else {
        // Memory copy failed - caught by signal handler
        recovery_buffer_ready = 0;
        return 0;
    }
}