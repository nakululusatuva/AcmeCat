cmake_minimum_required(VERSION 3.14)
project(acmecat)

# C++ 17 Standard
set(CMAKE_CXX_STANDARD 17)
# Suppress all warnings if not debug build.
if (${CMAKE_BUILD_TYPE} STREQUAL Debug)
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -Wextra")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
else()
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wno-all -Wno-deprecated -Wno-deprecated-declarations")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-all -Wno-deprecated -Wno-deprecated-declarations")
endif ()
# Optimize Level
if (OPTIMIZE_LEVEL)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O${OPTIMIZE_LEVEL}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O${OPTIMIZE_LEVEL}")
endif ()

# If build with static OpenSSL library.
if (STATIC_OPENSSL)
    set(LINK_OPTIONS "-static-libgcc -static-libstdc++ -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl -pthread")
else()
    set(LINK_OPTIONS "-static-libgcc -static-libstdc++ -lssl -lcrypto -ldl -pthread")
endif()
# OpenSSL path
if (OPENSSL_INCLUDE)
    include_directories(${OPENSSL_INCLUDE})
endif()
if(OPENSSL_LIB)
    link_directories(${OPENSSL_LIB})
endif()

# Add project source
aux_source_directory(./src SRCS)
# Add project libraries
add_subdirectory(${PROJECT_SOURCE_DIR}/src/acme)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/distribution)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/utils)
set (LIBS ${LIBS} acme distribution utils)
# Add dependent libraries
add_subdirectory(${PROJECT_SOURCE_DIR}/src/utils/easyloggingpp)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/utils/jsoncpp/src/lib_json)
set (LIBS ${LIBS} easyloggingpp jsoncpp_lib)

# Executable
add_executable(acmecat ${SRCS})
target_link_libraries(acmecat ${LIBS} ${LINK_OPTIONS})
