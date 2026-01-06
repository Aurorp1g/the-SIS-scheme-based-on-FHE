# 基于FHE的SIS方案项目构建脚本
# 项目基本信息配置
cmake_minimum_required(VERSION 3.16)
project(the-SIS-scheme-based-on-FHE VERSION 1.0 LANGUAGES CXX)

# C++标准配置
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译器特定的C++17支持
if(MSVC)
    add_compile_options(/std:c++17)
else()
    add_compile_options(-std=c++17)
endif()

# 默认构建类型设置
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# 编译器警告和链接选项配置
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -pedantic -Wno-deprecated -Wno-unused-parameter -Wno-deprecated-copy -Wno-sign-compare)
    if(WIN32)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
elseif(MSVC)
    add_compile_options(/W4 /wd4100 /wd4996 /wd4244 /wd4267)
    if(WIN32)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MT")
    endif()
endif()

# 构建选项配置
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_EXAMPLES "Build examples" ON)

# SEAL库路径配置
set(SEAL_ROOT_DIR ${CMAKE_SOURCE_DIR}/plugins/SEAL)

# SEAL库检测和配置
if(EXISTS "${SEAL_ROOT_DIR}/lib/libseal.a")
    set(SEAL_INCLUDE_DIR ${SEAL_ROOT_DIR}/include)
    set(SEAL_LIBRARIES ${SEAL_ROOT_DIR}/lib/libseal.a)
    set(SEAL_FOUND TRUE)
    message(STATUS "找到SEAL库: ${SEAL_LIBRARIES}")
    
    # 检查SEAL版本
    if(EXISTS "${SEAL_ROOT_DIR}/include/seal/util/config.h")
        file(STRINGS "${SEAL_ROOT_DIR}/include/seal/util/config.h" SEAL_VERSION_LINE REGEX "^#define SEAL_VERSION")
        if(SEAL_VERSION_LINE)
            string(REGEX REPLACE "^#define SEAL_VERSION \"([^\"]+)\"" "\\1" SEAL_VERSION "${SEAL_VERSION_LINE}")
            message(STATUS "SEAL库版本: ${SEAL_VERSION}")
        endif()
    endif()
else()
    set(SEAL_FOUND FALSE)
    message(FATAL_ERROR "未找到SEAL库，请确保SEAL库已正确安装在plugins/SEAL目录下")
endif()

# 创建主可执行文件
add_executable(sis-scheme-main)

# 主源文件配置
target_sources(sis-scheme-main PRIVATE
    src/CKKS.cpp
)

# 包含目录配置
target_include_directories(sis-scheme-main PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${SEAL_INCLUDE_DIR}
)

# 编译器选项配置
target_compile_options(sis-scheme-main PRIVATE 
    $<$<CXX_COMPILER_ID:MSVC>:/wd4100 /wd4996>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-unused-parameter -Wno-deprecated-copy -Wno-pedantic>
)

# 链接SEAL库
target_link_libraries(sis-scheme-main PRIVATE
    ${SEAL_LIBRARIES}
)

# Windows平台特定链接库
if(WIN32)
    target_link_libraries(sis-scheme-main PRIVATE
        bcrypt
        crypt32
        ws2_32
    )
else()
    # Linux/Mac平台特定链接库
    target_link_libraries(sis-scheme-main PRIVATE
        pthread
    )
endif()

# 安装配置
install(TARGETS sis-scheme-main
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# 配置摘要输出
message(STATUS "========================================")
message(STATUS "配置摘要:")
message(STATUS "  项目: ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  编译器: ${CMAKE_CXX_COMPILER}")
message(STATUS "  构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++标准: ${CMAKE_CXX_STANDARD}")
message(STATUS "  启用测试: ${BUILD_TESTS}")
message(STATUS "  启用示例: ${BUILD_EXAMPLES}")
message(STATUS "  SEAL库: ${SEAL_FOUND}")
if(SEAL_FOUND)
    message(STATUS "  SEAL版本: ${SEAL_VERSION}")
endif()
message(STATUS "========================================")