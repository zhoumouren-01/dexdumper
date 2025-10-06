#ifndef DEXDUMPER_EXPORT_H
#define DEXDUMPER_EXPORT_H

// Export header file - defines public API for the library
// This is what other applications would use to interact with DexDumper

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Starts the DEX dumping process
 * 
 * This function initializes and begins scanning memory for DEX files.
 * It typically runs in a background thread.
 */
void start_dex_dumping(void);

/**
 * @brief Stops the DEX dumping process
 * 
 * This function safely terminates any ongoing dumping operations
 * and cleans up resources.
 */
void stop_dex_dumping(void);

#ifdef __cplusplus
}
#endif

#endif