cmake_minimum_required(VERSION 3.20)

project(
    Cryptography
    VERSION 1.0
    LANGUAGES CXX
)

# Lab specification requires C++17 or later.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Helps VS Code IntelliSense / clangd.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Lab 6 requires OpenSSL 3.5+ for ML-DSA and ML-KEM.
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

# --------------------------------------------------
# Crypto++ configuration
# --------------------------------------------------

# Can be overridden from the CMake command line:
# cmake -S . -B build -DCRYPTOPP_ROOT=D:/cryptopp_lib
set(
    CRYPTOPP_ROOT
    "D:/cryptopp_lib"
    CACHE PATH
    "Root directory of the Crypto++ installation"
)

find_path(
    CRYPTOPP_INCLUDE_DIR
    NAMES cryptopp/aes.h
    PATHS
        "${CRYPTOPP_ROOT}/include"
    REQUIRED
)

find_library(
    CRYPTOPP_LIBRARY
    NAMES
        cryptopp
        libcryptopp
    PATHS
        "${CRYPTOPP_ROOT}/lib/cryptopp/gcc"
        "${CRYPTOPP_ROOT}/lib"
    REQUIRED
)

# Create an imported Crypto++ target.
add_library(CryptoPP::CryptoPP UNKNOWN IMPORTED)

set_target_properties(
    CryptoPP::CryptoPP
    PROPERTIES
        IMPORTED_LOCATION "${CRYPTOPP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_INCLUDE_DIR}"
)

# --------------------------------------------------
# Executables
# --------------------------------------------------

add_executable(Lab1
    Lab1/Lab1.cpp
)

add_executable(Lab3
    Lab3/Lab3.cpp
)

add_executable(Lab4
    Lab4/Lab4.cpp
)

add_executable(Lab5
    Lab5/Lab5.cpp
)

add_executable(Lab6
    Lab6/Lab6.cpp
)

# --------------------------------------------------
# Dependencies
# --------------------------------------------------

# Lab 1: Crypto++ only
target_link_libraries(
    Lab1
    PRIVATE
        CryptoPP::CryptoPP
)

# Lab 3: OpenSSL
target_link_libraries(
    Lab3
    PRIVATE
        OpenSSL::Crypto
)

# Lab 4: Crypto++ and OpenSSL
target_link_libraries(
    Lab4
    PRIVATE
        CryptoPP::CryptoPP
        OpenSSL::Crypto
)

# Lab 5: OpenSSL
target_link_libraries(
    Lab5
    PRIVATE
        OpenSSL::Crypto
)

# Lab 6: OpenSSL 3.5+
target_link_libraries(
    Lab6
    PRIVATE
        OpenSSL::Crypto
)

# --------------------------------------------------
# Compiler warnings
# --------------------------------------------------

if(MSVC)
    target_compile_options(Lab1 PRIVATE /W4)
    target_compile_options(Lab3 PRIVATE /W4)
    target_compile_options(Lab4 PRIVATE /W4)
    target_compile_options(Lab5 PRIVATE /W4)
    target_compile_options(Lab6 PRIVATE /W4)
else()
    target_compile_options(Lab1 PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(Lab3 PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(Lab4 PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(Lab5 PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(Lab6 PRIVATE -Wall -Wextra -Wpedantic)
endif()

# -mconsole is only relevant to MinGW on Windows.
if(MINGW)
    target_link_options(Lab1 PRIVATE -mconsole)
    target_link_options(Lab3 PRIVATE -mconsole)
    target_link_options(Lab4 PRIVATE -mconsole)
    target_link_options(Lab5 PRIVATE -mconsole)
    target_link_options(Lab6 PRIVATE -mconsole)
endif()
# --------------------------------------------------
# Automated tests (CTest)
# --------------------------------------------------
include(CTest)

if(BUILD_TESTING)
    # Every test runs in its own directory so generated keys and temporary
    # files never pollute the source tree or conflict with parallel tests.
    function(add_crypto_test TEST_NAME TARGET_NAME)
        set(TEST_DIR "${CMAKE_CURRENT_BINARY_DIR}/test-work/${TEST_NAME}")
        file(MAKE_DIRECTORY "${TEST_DIR}")
        add_test(NAME "${TEST_NAME}" COMMAND $<TARGET_FILE:${TARGET_NAME}> ${ARGN})
        set_tests_properties("${TEST_NAME}" PROPERTIES
            WORKING_DIRECTORY "${TEST_DIR}"
            TIMEOUT 180
        )
    endfunction()

    # Lab 1: official AES known-answer vectors and security negative tests.
    add_crypto_test(Lab1_KAT Lab1 kat)
    set_tests_properties(Lab1_KAT PROPERTIES
        PASS_REGULAR_EXPRESSION "KAT summary: 7/7 passed"
        LABELS "Lab1;Negative;AES"
    )

    add_crypto_test(Lab1_SelfTest Lab1 selftest)
    set_tests_properties(Lab1_SelfTest PROPERTIES
        PASS_REGULAR_EXPRESSION "Self-test summary: 14/14 passed"
        LABELS "Lab1;Negative;AES"
    )

    # Lab 3: manual OAEP encode/decode and fail-closed negative cases.
    add_crypto_test(Lab3_OAEP_SelfTest Lab3 test-oaep)
    set_tests_properties(Lab3_OAEP_SelfTest PROPERTIES
        PASS_REGULAR_EXPRESSION "ALL TESTS PASSED"
        LABELS "Lab3;OAEP;RSA;Negative"
        TIMEOUT 300
    )

    # Lab 4: SHA-2, SHA-3 and SHAKE known-answer vectors.
    add_crypto_test(Lab4_Hash_KAT Lab4 kat)
    set_tests_properties(Lab4_Hash_KAT PROPERTIES
        PASS_REGULAR_EXPRESSION "\\[PASS\\] shake256"
        LABELS "Lab4;KAT;Hash"
    )

    # Lab 5: signature correctness plus tampered message/signature/wrong key.
    add_crypto_test(Lab5_Signature_SelfTest Lab5 test)
    set_tests_properties(Lab5_Signature_SelfTest PROPERTIES
        PASS_REGULAR_EXPRESSION "ALL AUTOMATED TESTS PASSED"
        LABELS "Lab5;ECDSA;Signature;Negative"
        TIMEOUT 300
    )

    # Lab 6: ML-DSA and ML-KEM correctness and negative cases.
    add_crypto_test(Lab6_PQC_SelfTest Lab6 selftest)
    set_tests_properties(Lab6_PQC_SelfTest PROPERTIES
        PASS_REGULAR_EXPRESSION "Self-test summary: 17/17 passed"
        LABELS "Lab6;PQC;ML-DSA;ML-KEM;Negative"
        TIMEOUT 300
    )

    # CLI malformed-command checks: each tool must fail closed.
    foreach(LAB_TARGET IN ITEMS Lab1 Lab3 Lab4 Lab5 Lab6)
        add_crypto_test(${LAB_TARGET}_Rejects_Unknown_Command ${LAB_TARGET}
                        definitely-not-a-command)
        set_tests_properties(${LAB_TARGET}_Rejects_Unknown_Command PROPERTIES
            WILL_FAIL TRUE
            LABELS "${LAB_TARGET};CLI;Negative"
        )
    endforeach()
endif()