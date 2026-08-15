# ============================================================================
#  Sentinel - top-level build configuration
#
#  Primary build system for the project. Stage 1 builds a single Win32 GUI
#  executable from the C sources. Later stages will add the scanner/analysis/
#  binary/reporting/database modules and (optionally) SQLite + NASM objects.
# ============================================================================
cmake_minimum_required(VERSION 3.16)
project(Sentinel LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# ---- Sources (grow this list as stages are added) --------------------------
set(SENTINEL_SOURCES
    src/main.c
    src/ui.c
    src/system/sysinfo.c
    src/scanner/scanner.c
)

# WIN32 => GUI subsystem (uses WinMain, no console window).
add_executable(Sentinel WIN32 ${SENTINEL_SOURCES})

target_include_directories(Sentinel PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(Sentinel PRIVATE
        gdi32 user32 advapi32 bcrypt shell32 ole32)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(Sentinel PRIVATE -Wall -Wextra)
endif()

# Emit the executable at <build>/Sentinel.exe so the VS Code launch config
# and the fallback build script always agree on the output path.
set_target_properties(Sentinel PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
