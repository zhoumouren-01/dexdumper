#include "stealth.h"

/**
 * @brief Applies anti-detection techniques to hide dumping activity
 * 
 * This function implements various techniques to make the dumping process
 * less conspicuous to detection systems and analysis tools.
 * 
 * Current techniques:
 * - Thread name spoofing: Changes thread name to common Android system names
 * - Random delays: Adds unpredictable timing to avoid pattern detection
 */
void apply_stealth_techniques() {
    // Pool of common Android thread names for spoofing
    const char* thread_name_pool[] = {
        "Binder:", "JDWP", "Finalizer", "GC", "Signal Catcher",
        "hwuiTask", "RenderThread", "BgThread", "PoolThread",
        "AsyncTask", "Thread", "OkHttp", "Retrofit"
    };
    
    // Randomly select a thread name from the pool
    int name_index = rand() % (sizeof(thread_name_pool)/sizeof(thread_name_pool[0]));
    char temporary_thread_name[16];
    
    // Copy selected name with bounds checking
    strncpy(temporary_thread_name, thread_name_pool[name_index], sizeof(temporary_thread_name) - 1);
    temporary_thread_name[sizeof(temporary_thread_name) - 1] = '\0';

    // Set thread name to spoofed name
#if defined(_GNU_SOURCE) || defined(__ANDROID__)
    pthread_setname_np(pthread_self(), temporary_thread_name);
#else
    prctl(PR_SET_NAME, (unsigned long)temporary_thread_name, 0, 0, 0);
#endif

    // Add random delay to avoid predictable timing patterns
    usleep(100000 + (rand() % 400000)); // 100-500ms random delay
}