cmake_minimum_required(VERSION 3.10)
project(PasswordManagerProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/db_manager.cpp
    src/password_manager.cpp
    src/aes.cpp
)

# Create executable
add_executable(password_manager ${SOURCES})

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Link MySQL C++ Connector
find_library(MYSQLCPP_CONN_LIB mysqlcppconn)

if(NOT MYSQLCPP_CONN_LIB)
    message(FATAL_ERROR "MySQL C++ Connector library not found. Install libmysqlcppconn-dev")
endif()

# Find Crypto++ library
find_library(CRYPTOPP_LIB cryptopp)

if(NOT CRYPTOPP_LIB)
    message(FATAL_ERROR "Crypto++ library not found. Install libcrypto++-dev")
endif()

# Link libraries
target_link_libraries(password_manager
    OpenSSL::SSL
    OpenSSL::Crypto
    ${MYSQLCPP_CONN_LIB}
    ${CRYPTOPP_LIB}
    Threads::Threads
)
