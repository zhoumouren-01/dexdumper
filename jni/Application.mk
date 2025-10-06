# Application.mk - Android NDK application configuration
# Defines build targets and platform requirements

# Target CPU architectures
APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
# armeabi-v7a: 32-bit ARM
# arm64-v8a: 64-bit ARM  
# x86, x86_64: Intel architectures

APP_PLATFORM := android-21  # Minimum Android version (5.0 Lollipop)
APP_STL := c++_static       # Use static C++ runtime

# Compiler flags for all modules
APP_CFLAGS := -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden -O2
APP_CPPFLAGS := -std=c++11  # C++11 standard