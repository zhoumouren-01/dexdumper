# Android.mk - Android NDK build configuration
# Used by ndk-build system

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Module name - will generate libdexdumper.so
LOCAL_MODULE := dexdumper

# Source files to compile
LOCAL_SRC_FILES := \
	../src/main.c \
	../src/signal_handler.c \
	../src/file_utils.c \
	../src/registry_manager.c \
	../src/memory_scanner.c \
	../src/dex_detector.c \
	../src/stealth.c \
	../src/sha1.c \
	../src/config_manager.c

# Compiler flags
LOCAL_CFLAGS := -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden -O2
# -fvisibility=hidden: Hide internal symbols
# -O2: Optimization for performance

LOCAL_LDFLAGS := -Wl,--build-id=sha1  # Use SHA1 for build IDs
LOCAL_LDLIBS := -llog -landroid       # Link Android libraries

# Build as shared library
include $(BUILD_SHARED_LIBRARY)