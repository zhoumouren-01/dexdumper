#ifndef DEXDUMPER_SIGNAL_HANDLER_H
#define DEXDUMPER_SIGNAL_HANDLER_H

// Signal handler header - declares safe memory access functions

#include "common.h"
#include "config.h"

/**
 * Safe Memory Access System:
 * 
 * These functions use signal handling to safely probe and read memory
 * without crashing when encountering protected or invalid regions.
 * Essential for scanning unknown process memory.
 */

// Installs signal handlers for memory access violations
void install_memory_signal_handlers(void);

// Validates that memory range can be safely accessed
int validate_memory_access(const void* memory_address, size_t memory_size);

// Safely copies memory with signal protection
int read_memory_safely(const void* source_address, void* destination_buffer, 
                      size_t read_size);

// Thread-local recovery context for signal handling
extern __thread sigjmp_buf signal_recovery_buffer;
extern __thread volatile sig_atomic_t recovery_buffer_ready;

// Global signal handling state
extern pthread_mutex_t signal_handler_mutex;
extern int signal_handlers_installed;
extern stack_t signal_handler_stack;

#endif