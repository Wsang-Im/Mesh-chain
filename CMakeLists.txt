cmake_minimum_required(VERSION 3.15)
project(MeshChainSimulation CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output all executables to build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Function to create launcher script for each executable
function(create_launcher target_name)
    set(EXECUTABLE_NAME ${target_name})
    configure_file(
        ${CMAKE_SOURCE_DIR}/scripts/launcher_template.sh.in
        ${CMAKE_BINARY_DIR}/${target_name}.sh
        @ONLY
    )
    file(CHMOD ${CMAKE_BINARY_DIR}/${target_name}.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )
endfunction()

# Build mode options
option(ALLOW_SIMULATION_MODE "Allow fallback to simulation mode if libraries not found" OFF)
option(REQUIRE_REAL_LIBRARIES "Require real libraries (SUMO, liboqs, libsodium) for production build" ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
)

# Source files - Original standalone simulator
set(SOURCES_STANDALONE
    src/main.cpp
)

# Source files - Integrated simulator with SUMO/WAVE
set(SOURCES_INTEGRATED
    src/main_integrated.cpp
)

# Source files - Rural road scenario
set(SOURCES_RURAL
    src/main_rural.cpp
)

# Headers (for IDE support)
set(HEADERS
    src/common/types.h
    src/common/block.h
    src/common/merkle_tree.h
    src/common/v2x_messages.h
    src/crypto/pqc_signatures.h
    src/crypto/liboqs_wrapper.h
    src/crypto/secure_channel.h
    src/crypto/tls13_channel.h
    src/crypto/tof_measurement.h
    src/crypto/extensibility.h
    src/storage/shamir_secret_sharing.h
    src/vehicle/witness_selection.h
    src/vehicle/block_creator.h
    src/network/omnetpp_interface.h
    src/rsu/anchor_system.h
    src/integration/traci_client.h
    src/integration/wave_stack.h
    src/integration/tof_adapter.h
    src/integration/integrated_vehicle.h
    src/security/attacker_models.h
)

# Executables
add_executable(meshchain_sim ${SOURCES_STANDALONE} ${HEADERS})
add_executable(meshchain_integrated ${SOURCES_INTEGRATED} ${HEADERS})
add_executable(meshchain_rural ${SOURCES_RURAL} ${HEADERS})
add_executable(meshchain_integrated_attack src/main_integrated_attack.cpp src/security/attacker_models.cpp ${HEADERS})

# Create launchers for main executables
create_launcher(meshchain_sim)
create_launcher(meshchain_integrated)
create_launcher(meshchain_rural)
create_launcher(meshchain_integrated_attack)

# Link libraries
target_link_libraries(meshchain_sim pthread)
target_link_libraries(meshchain_integrated pthread)
target_link_libraries(meshchain_rural pthread)
target_link_libraries(meshchain_integrated_attack pthread)

# Link with liboqs for PQC implementation
if(ALLOW_SIMULATION_MODE)
    find_package(liboqs QUIET)
    find_package(OpenSSL QUIET)
else()
    # Production mode: REQUIRE real libraries
    find_package(liboqs REQUIRED)
    find_package(OpenSSL REQUIRED)
endif()

if(liboqs_FOUND)
    message(STATUS "✓ liboqs found - enabling real PQC crypto (FALCON-512, ML-KEM-768, Dilithium-3)")
    target_link_libraries(meshchain_sim oqs)
    target_link_libraries(meshchain_integrated oqs)
    target_link_libraries(meshchain_rural oqs)
    target_link_libraries(meshchain_integrated_attack oqs)
    target_compile_definitions(meshchain_sim PRIVATE USE_LIBOQS)
    target_compile_definitions(meshchain_integrated PRIVATE USE_LIBOQS)
    target_compile_definitions(meshchain_rural PRIVATE USE_LIBOQS)
    target_compile_definitions(meshchain_integrated_attack PRIVATE USE_LIBOQS)

    # liboqs depends on OpenSSL
    if(OPENSSL_FOUND)
        target_link_libraries(meshchain_sim OpenSSL::Crypto)
        target_link_libraries(meshchain_integrated OpenSSL::Crypto)
        target_link_libraries(meshchain_rural OpenSSL::Crypto)
        target_link_libraries(meshchain_integrated_attack OpenSSL::Crypto)
        target_compile_definitions(meshchain_sim PRIVATE USE_OPENSSL_SHA3)
        target_compile_definitions(meshchain_integrated PRIVATE USE_OPENSSL_SHA3)
        target_compile_definitions(meshchain_rural PRIVATE USE_OPENSSL_SHA3)
        target_compile_definitions(meshchain_integrated_attack PRIVATE USE_OPENSSL_SHA3)
        message(STATUS "✓ OpenSSL found - enabling SHA3-256 and linking with liboqs")
    else()
        message(FATAL_ERROR "OpenSSL is required for liboqs. Install: sudo apt-get install libssl-dev")
    endif()
else()
    if(ALLOW_SIMULATION_MODE)
        message(WARNING "⚠ liboqs not found - using SIMULATION MODE (NOT for production!)")
        message(STATUS "  Install liboqs: https://github.com/open-quantum-safe/liboqs")
        message(STATUS "  Or set -DALLOW_SIMULATION_MODE=OFF to enforce real libraries")
    else()
        message(FATAL_ERROR "liboqs is REQUIRED. Install from: https://github.com/open-quantum-safe/liboqs")
    endif()
endif()

# Link with libsodium for AEAD (XChaCha20-Poly1305)
find_package(PkgConfig REQUIRED)
if(ALLOW_SIMULATION_MODE)
    pkg_check_modules(SODIUM libsodium)
else()
    # Production mode: REQUIRE libsodium
    pkg_check_modules(SODIUM REQUIRED libsodium)
endif()

if(SODIUM_FOUND)
    message(STATUS "✓ libsodium found - enabling real AEAD encryption (XChaCha20-Poly1305)")
    message(STATUS "  Version: ${SODIUM_VERSION}")
    message(STATUS "  Include dirs: ${SODIUM_INCLUDE_DIRS}")
    message(STATUS "  Libraries: ${SODIUM_LIBRARIES}")

    include_directories(${SODIUM_INCLUDE_DIRS})
    link_directories(${SODIUM_LIBRARY_DIRS})

    target_link_libraries(meshchain_sim ${SODIUM_LIBRARIES})
    target_link_libraries(meshchain_integrated ${SODIUM_LIBRARIES})
    target_link_libraries(meshchain_rural ${SODIUM_LIBRARIES})
    target_link_libraries(meshchain_integrated_attack ${SODIUM_LIBRARIES})
    target_compile_definitions(meshchain_sim PRIVATE USE_LIBSODIUM)
    target_compile_definitions(meshchain_integrated PRIVATE USE_LIBSODIUM)
    target_compile_definitions(meshchain_rural PRIVATE USE_LIBSODIUM)
    target_compile_definitions(meshchain_integrated_attack PRIVATE USE_LIBSODIUM)
else()
    if(ALLOW_SIMULATION_MODE)
        message(WARNING "⚠ libsodium not found - using SIMULATION MODE for AEAD (NOT for production!)")
        message(STATUS "  Install: sudo apt-get install libsodium-dev")
    else()
        message(FATAL_ERROR "libsodium is REQUIRED. Install: sudo apt-get install libsodium-dev")
    endif()
endif()

# Link with libsumo for SUMO integration (TraCI)
# libsumo is part of SUMO installation
find_path(LIBSUMO_INCLUDE_DIR
    NAMES libsumo/libsumo.h
    PATHS
        /usr/include
        /usr/local/include
        $ENV{SUMO_HOME}/src
)

find_library(LIBSUMO_LIBRARY
    NAMES sumocpp sumo libsumo
    PATHS
        /usr/lib
        /usr/local/lib
        $ENV{SUMO_HOME}/bin
)

if(LIBSUMO_INCLUDE_DIR AND LIBSUMO_LIBRARY)
    message(STATUS "✓ libsumo found - enabling REAL SUMO integration via TraCI")
    message(STATUS "  Include: ${LIBSUMO_INCLUDE_DIR}")
    message(STATUS "  Library: ${LIBSUMO_LIBRARY}")
    include_directories(${LIBSUMO_INCLUDE_DIR})
    target_link_libraries(meshchain_integrated ${LIBSUMO_LIBRARY})
    target_link_libraries(meshchain_rural ${LIBSUMO_LIBRARY})
    target_link_libraries(meshchain_integrated_attack ${LIBSUMO_LIBRARY})
    target_compile_definitions(meshchain_integrated PRIVATE USE_TRACI)
    target_compile_definitions(meshchain_rural PRIVATE USE_TRACI)
    target_compile_definitions(meshchain_integrated_attack PRIVATE USE_TRACI)
else()
    if(ALLOW_SIMULATION_MODE)
        message(WARNING "⚠ libsumo not found - integrated simulator will run in MOCK MODE (NOT for production!)")
        message(STATUS "  Install SUMO and set SUMO_HOME environment variable")
        message(STATUS "  https://sumo.dlr.de/docs/Installing/index.html")
    else()
        message(FATAL_ERROR "libsumo is REQUIRED for meshchain_integrated. Install SUMO from: https://sumo.dlr.de/docs/Installing/index.html")
    endif()
endif()

# Link with cpp-libp2p for P2P networking (DHT, GossipSub, Bitswap)
# NOTE: For V2X simulation, STUB mode is sufficient (all vehicles in same process)
# REAL libp2p only needed for production deployment across internet
# Currently disabled - using STUB implementation

find_path(LIBP2P_INCLUDE_DIR
    NAMES libp2p/host/host.hpp
    PATHS
        /usr/include
        /usr/local/include
        $ENV{LIBP2P_ROOT}/include
)

find_library(LIBP2P_LIBRARY
    NAMES p2p libp2p
    PATHS
        /usr/lib
        /usr/local/lib
        $ENV{LIBP2P_ROOT}/lib
)

# Disable libp2p for now - simulation-optimized mode sufficient for in-process V2X simulation
if(FALSE AND LIBP2P_INCLUDE_DIR AND LIBP2P_LIBRARY)
    message(STATUS "✓ cpp-libp2p found - enabling REAL P2P networking")
    message(STATUS "  Include: ${LIBP2P_INCLUDE_DIR}")
    message(STATUS "  Library: ${LIBP2P_LIBRARY}")
    include_directories(${LIBP2P_INCLUDE_DIR})
    target_link_libraries(meshchain_sim ${LIBP2P_LIBRARY})
    target_link_libraries(meshchain_integrated ${LIBP2P_LIBRARY})
    target_link_libraries(meshchain_rural ${LIBP2P_LIBRARY})
    target_compile_definitions(meshchain_sim PRIVATE USE_CPP_LIBP2P)
    target_compile_definitions(meshchain_integrated PRIVATE USE_CPP_LIBP2P)
    target_compile_definitions(meshchain_rural PRIVATE USE_CPP_LIBP2P)
else()
    message(STATUS "ℹ cpp-libp2p not enabled - using simulation-optimized P2P implementation")
    message(STATUS "  This is acceptable for V2X simulation (all vehicles in same process)")
    message(STATUS "  For distributed deployment: Install cpp-libp2p from https://github.com/libp2p/cpp-libp2p")
endif()

# Network simulation options
# Option 1: OMNeT++ + Veins (recommended if installed)
# Option 2: ns-3 WAVE
# Option 3: Queue-based (fallback)
option(USE_OMNETPP_VEINS "Enable OMNeT++/Veins for realistic IEEE 802.11p simulation" OFF)
option(USE_NS3_WAVE "Enable ns-3 WAVE module for realistic IEEE 802.11p simulation" OFF)

# Link with OMNeT++ and Veins for realistic IEEE 802.11p WAVE simulation
if(USE_OMNETPP_VEINS)
    # Find OMNeT++
    find_path(OMNETPP_INCLUDE_DIR
        NAMES omnetpp.h
        PATHS
            $HOME/omnetpp/omnetpp-6.0.3/include
            /usr/include/omnetpp
            /usr/local/include/omnetpp
            $ENV{OMNETPP_ROOT}/include
    )

    find_library(OMNETPP_LIBRARY
        NAMES oppsim oppsimd
        PATHS
            $HOME/omnetpp/omnetpp-6.0.3/lib
            /usr/lib/omnetpp
            /usr/local/lib/omnetpp
            $ENV{OMNETPP_ROOT}/lib
    )

    # Find Veins
    find_path(VEINS_INCLUDE_DIR
        NAMES veins/veins.h
        PATHS
            $HOME/src/veins/src
            /usr/include/veins
            /usr/local/include/veins
            $ENV{VEINS_ROOT}/src
    )

    find_library(VEINS_LIBRARY
        NAMES veins
        PATHS
            $HOME/src/veins/out/gcc-release/src
            /usr/lib/veins
            /usr/local/lib/veins
            $ENV{VEINS_ROOT}/out/gcc-release/src
    )

    if(OMNETPP_INCLUDE_DIR AND OMNETPP_LIBRARY AND VEINS_INCLUDE_DIR)
        message(STATUS "✓ OMNeT++/Veins found - enabling realistic IEEE 802.11p WAVE simulation")
        message(STATUS "  OMNeT++ include: ${OMNETPP_INCLUDE_DIR}")
        message(STATUS "  OMNeT++ library: ${OMNETPP_LIBRARY}")
        message(STATUS "  Veins include: ${VEINS_INCLUDE_DIR}")

        include_directories(${OMNETPP_INCLUDE_DIR})
        include_directories(${VEINS_INCLUDE_DIR})

        target_link_libraries(meshchain_integrated ${OMNETPP_LIBRARY})
        target_link_libraries(meshchain_rural ${OMNETPP_LIBRARY})

        if(VEINS_LIBRARY)
            target_link_libraries(meshchain_integrated ${VEINS_LIBRARY})
            target_link_libraries(meshchain_rural ${VEINS_LIBRARY})
        endif()

        target_compile_definitions(meshchain_integrated PRIVATE USE_OMNETPP_VEINS)
        target_compile_definitions(meshchain_rural PRIVATE USE_OMNETPP_VEINS)

        message(STATUS "  ⚡ WAVE stack will use OMNeT++/Veins for realistic PHY/MAC simulation")
        message(STATUS "  - CSMA/CA with backoff and collision detection")
        message(STATUS "  - Path loss, shadowing, and fading models")
        message(STATUS "  - SNR-based packet error rate")
    else()
        message(WARNING "⚠ OMNeT++/Veins not found - WAVE will use fallback simulation")
        message(STATUS "  Install OMNeT++: https://omnetpp.org/")
        message(STATUS "  Install Veins: https://veins.car2x.org/")
        message(STATUS "  Current simulation still works but with simplified wireless model")
    endif()
elseif(USE_NS3_WAVE)
    # Try to find ns-3 via pkg-config
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(NS3 QUIET ns3-dev)
        if(NOT NS3_FOUND)
            pkg_check_modules(NS3 QUIET libns3-dev)
        endif()
    endif()

    # Try manual search if pkg-config failed
    if(NOT NS3_FOUND)
        find_path(NS3_INCLUDE_DIR
            NAMES ns3/core-module.h
            PATHS
                /usr/include
                /usr/local/include
                /usr/include/ns3.37
                /usr/include/ns3.36
                /usr/local/include/ns3.37
                /usr/local/include/ns3.36
                $ENV{NS3_ROOT}/include
        )

        find_library(NS3_CORE_LIBRARY
            NAMES ns3-core ns3.37-core ns3.36-core libns3-core
            PATHS
                /usr/lib
                /usr/local/lib
                /usr/lib/x86_64-linux-gnu
                $ENV{NS3_ROOT}/lib
        )

        if(NS3_INCLUDE_DIR AND NS3_CORE_LIBRARY)
            set(NS3_FOUND TRUE)
            get_filename_component(NS3_LIBRARY_DIR ${NS3_CORE_LIBRARY} DIRECTORY)

            # Find all required ns-3 modules
            find_library(NS3_NETWORK_LIBRARY NAMES ns3-network ns3.37-network PATHS ${NS3_LIBRARY_DIR})
            find_library(NS3_WIFI_LIBRARY NAMES ns3-wifi ns3.37-wifi PATHS ${NS3_LIBRARY_DIR})
            find_library(NS3_WAVE_LIBRARY NAMES ns3-wave ns3.37-wave PATHS ${NS3_LIBRARY_DIR})
            find_library(NS3_MOBILITY_LIBRARY NAMES ns3-mobility ns3.37-mobility PATHS ${NS3_LIBRARY_DIR})
            find_library(NS3_PROPAGATION_LIBRARY NAMES ns3-propagation ns3.37-propagation PATHS ${NS3_LIBRARY_DIR})
            find_library(NS3_INTERNET_LIBRARY NAMES ns3-internet ns3.37-internet PATHS ${NS3_LIBRARY_DIR})

            set(NS3_LIBRARIES
                ${NS3_CORE_LIBRARY}
                ${NS3_NETWORK_LIBRARY}
                ${NS3_WIFI_LIBRARY}
                ${NS3_WAVE_LIBRARY}
                ${NS3_MOBILITY_LIBRARY}
                ${NS3_PROPAGATION_LIBRARY}
                ${NS3_INTERNET_LIBRARY}
            )
        endif()
    endif()

    if(NS3_FOUND)
        message(STATUS "✓ ns-3 found - enabling realistic IEEE 802.11p WAVE simulation")
        message(STATUS "  Include: ${NS3_INCLUDE_DIR}")
        message(STATUS "  Libraries: ${NS3_LIBRARIES}")

        include_directories(${NS3_INCLUDE_DIR})

        target_link_libraries(meshchain_integrated ${NS3_LIBRARIES})
        target_link_libraries(meshchain_rural ${NS3_LIBRARIES})
        target_compile_definitions(meshchain_integrated PRIVATE USE_NS3_WAVE)
        target_compile_definitions(meshchain_rural PRIVATE USE_NS3_WAVE)

        message(STATUS "  ⚡ WAVE stack will use ns-3 for realistic PHY/MAC layer simulation")
    else()
        message(WARNING "⚠ ns-3 not found - WAVE will use queue-based simulation")
        message(STATUS "  Install ns-3: sudo apt-get install ns3 (or build from source)")
        message(STATUS "  https://www.nsnam.org/wiki/Installation")
        message(STATUS "  Current simulation still works but with simplified wireless model")
    endif()
else()
    message(STATUS "ℹ ns-3 WAVE integration disabled (USE_NS3_WAVE=OFF)")
    message(STATUS "  Using queue-based WAVE simulation (suitable for functional testing)")
    message(STATUS "  To enable realistic IEEE 802.11p simulation: cmake -DUSE_NS3_WAVE=ON ..")
endif()

# Test executable for ZKP system
add_executable(test_zkp src/test_zkp.cpp)
target_link_libraries(test_zkp
    ${OQS_LIBRARY}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARY}
)
create_launcher(test_zkp)

# PQC Benchmark executable (standalone, no simulation dependencies)
add_executable(benchmark_pqc src/benchmark_pqc.cpp)
if(liboqs_FOUND AND OPENSSL_FOUND)
    target_link_libraries(benchmark_pqc oqs OpenSSL::Crypto pthread)
else()
    target_link_libraries(benchmark_pqc pthread)
endif()
create_launcher(benchmark_pqc)

# L2 Anchor Watcher (multi-simulation aggregator)
add_executable(l2_anchor_watcher src/l2_anchor_watcher.cpp)
target_link_libraries(l2_anchor_watcher pthread)
create_launcher(l2_anchor_watcher)

# Installation
install(TARGETS meshchain_sim meshchain_integrated meshchain_rural test_zkp benchmark_pqc l2_anchor_watcher
        RUNTIME DESTINATION bin)

# Tests (optional)
option(BUILD_TESTS "Build test suite" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "====================================================")
message(STATUS "  Mesh-Chain V2X Blockchain Simulation - Build Config")
message(STATUS "====================================================")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "")
message(STATUS "Build Mode:")
if(ALLOW_SIMULATION_MODE)
    message(STATUS "  ⚠ SIMULATION MODE ALLOWED (not for production)")
    message(STATUS "  Set -DALLOW_SIMULATION_MODE=OFF to require real libraries")
else()
    message(STATUS "  ✓ PRODUCTION MODE - Real libraries REQUIRED")
endif()
message(STATUS "")
message(STATUS "Required Libraries:")
if(liboqs_FOUND)
    message(STATUS "  ✓ liboqs (PQC): ENABLED")
else()
    message(STATUS "  ✗ liboqs (PQC): NOT FOUND")
endif()
if(OPENSSL_FOUND)
    message(STATUS "  ✓ OpenSSL (SHA3): ENABLED")
else()
    message(STATUS "  ✗ OpenSSL (SHA3): NOT FOUND")
endif()
if(SODIUM_FOUND)
    message(STATUS "  ✓ libsodium (AEAD): ENABLED")
else()
    message(STATUS "  ✗ libsodium (AEAD): NOT FOUND")
endif()
if(LIBSUMO_INCLUDE_DIR AND LIBSUMO_LIBRARY)
    message(STATUS "  ✓ libsumo (SUMO/TraCI): ENABLED")
else()
    message(STATUS "  ✗ libsumo (SUMO/TraCI): NOT FOUND")
endif()
# Note: cpp-libp2p is intentionally disabled (see line 211: if(FALSE AND ...))
# Using simulation-optimized in-process P2P for V2X scenarios
message(STATUS "  ℹ cpp-libp2p (P2P): Simulation-optimized mode (in-process)")

# Network simulation status
if(USE_OMNETPP_VEINS AND OMNETPP_INCLUDE_DIR AND VEINS_INCLUDE_DIR)
    message(STATUS "  ✓ WAVE Network: OMNeT++/Veins (realistic IEEE 802.11p)")
elseif(USE_NS3_WAVE AND NS3_FOUND)
    message(STATUS "  ✓ WAVE Network: ns-3 (realistic IEEE 802.11p)")
else()
    message(STATUS "  ℹ WAVE Network: Queue-based simulation (functional testing)")
endif()
message(STATUS "")
message(STATUS "Executables:")
message(STATUS "  - meshchain_sim (standalone)")
message(STATUS "  - meshchain_integrated (with SUMO)")
message(STATUS "====================================================")
message(STATUS "")

# Test: P2P Communication Logging (commented out - file not present)
# add_executable(test_p2p_logging test_p2p_logging.cpp)
# target_include_directories(test_p2p_logging PRIVATE ${CMAKE_SOURCE_DIR})

# Test: Complete P2P Communication Logging (commented out - file not present)
# add_executable(test_p2p_logging_complete test_p2p_logging_complete.cpp)
# target_include_directories(test_p2p_logging_complete PRIVATE ${CMAKE_SOURCE_DIR})

# Test: TLS 1.3 Secure Channel
add_executable(test_tls13 src/test_tls13.cpp)
target_include_directories(test_tls13 PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_tls13 oqs)
    target_compile_definitions(test_tls13 PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_tls13 OpenSSL::Crypto)
    endif()
endif()
if(SODIUM_FOUND)
    include_directories(${SODIUM_INCLUDE_DIRS})
    target_link_libraries(test_tls13 ${SODIUM_LIBRARIES})
    target_compile_definitions(test_tls13 PRIVATE USE_LIBSODIUM)
endif()
create_launcher(test_tls13)

# Test: Crypto Implementation Verification
add_executable(verify_crypto src/verify_crypto.cpp)
target_include_directories(verify_crypto PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(verify_crypto oqs)
    target_compile_definitions(verify_crypto PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(verify_crypto OpenSSL::Crypto)
    endif()
endif()
if(SODIUM_FOUND)
    include_directories(${SODIUM_INCLUDE_DIRS})
    target_link_libraries(verify_crypto ${SODIUM_LIBRARIES})
    target_compile_definitions(verify_crypto PRIVATE USE_LIBSODIUM)
endif()
create_launcher(verify_crypto)

# Test: Off-Chain Storage with AEAD Encryption
add_executable(test_offchain_storage src/test_offchain_storage.cpp)
target_include_directories(test_offchain_storage PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_offchain_storage oqs)
    target_compile_definitions(test_offchain_storage PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_offchain_storage OpenSSL::Crypto)
    endif()
endif()
if(SODIUM_FOUND)
    include_directories(${SODIUM_INCLUDE_DIRS})
    target_link_libraries(test_offchain_storage ${SODIUM_LIBRARIES})
    target_compile_definitions(test_offchain_storage PRIVATE USE_LIBSODIUM)
endif()
create_launcher(test_offchain_storage)

# Debug: Shamir + AEAD key test
add_executable(test_shamir_key src/test_shamir_key.cpp)
target_include_directories(test_shamir_key PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_shamir_key oqs)
    target_compile_definitions(test_shamir_key PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_shamir_key OpenSSL::Crypto)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_shamir_key ${SODIUM_LIBRARIES})
    target_compile_definitions(test_shamir_key PRIVATE USE_LIBSODIUM)
endif()
create_launcher(test_shamir_key)

# Attack Scenario Test (validates robustness against T1, T2, T3, T6)
add_executable(attack_scenario_test
    src/attack_scenario_test.cpp
    src/security/attacker_models.cpp
)
target_include_directories(attack_scenario_test PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(attack_scenario_test oqs)
    target_compile_definitions(attack_scenario_test PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(attack_scenario_test OpenSSL::Crypto)
        target_compile_definitions(attack_scenario_test PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(attack_scenario_test ${SODIUM_LIBRARIES})
    target_compile_definitions(attack_scenario_test PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(attack_scenario_test pthread)
create_launcher(attack_scenario_test)

# Merkle Proof Generation Test (validates SHA-256 based Merkle tree implementation)
add_executable(test_merkle_proof src/test_merkle_proof.cpp)
target_include_directories(test_merkle_proof PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_merkle_proof oqs)
    target_compile_definitions(test_merkle_proof PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_merkle_proof OpenSSL::Crypto)
        target_compile_definitions(test_merkle_proof PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_merkle_proof ${SODIUM_LIBRARIES})
    target_compile_definitions(test_merkle_proof PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(test_merkle_proof pthread)
create_launcher(test_merkle_proof)

# FALCON Signature Verification Test (validates FALCON-512 signature verification)
add_executable(test_falcon_verification src/test_falcon_verification.cpp)
target_include_directories(test_falcon_verification PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_falcon_verification oqs)
    target_compile_definitions(test_falcon_verification PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_falcon_verification OpenSSL::Crypto)
        target_compile_definitions(test_falcon_verification PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_falcon_verification ${SODIUM_LIBRARIES})
    target_compile_definitions(test_falcon_verification PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(test_falcon_verification pthread)
create_launcher(test_falcon_verification)

# FALCON Integration Test (validates IntegratedVehicle signature verification)
add_executable(test_falcon_integration src/test_falcon_integration.cpp)
target_include_directories(test_falcon_integration PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_falcon_integration oqs)
    target_compile_definitions(test_falcon_integration PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_falcon_integration OpenSSL::Crypto)
        target_compile_definitions(test_falcon_integration PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_falcon_integration ${SODIUM_LIBRARIES})
    target_compile_definitions(test_falcon_integration PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(test_falcon_integration pthread)
create_launcher(test_falcon_integration)

# Witness Tracking Test (validates IntegratedVehicle witness tracking and silent witness penalty)
add_executable(test_witness_tracking src/test_witness_tracking.cpp)
target_include_directories(test_witness_tracking PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_witness_tracking oqs)
    target_compile_definitions(test_witness_tracking PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_witness_tracking OpenSSL::Crypto)
        target_compile_definitions(test_witness_tracking PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_witness_tracking ${SODIUM_LIBRARIES})
    target_compile_definitions(test_witness_tracking PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(test_witness_tracking pthread)
create_launcher(test_witness_tracking)

# Defense Resilience Test (validates defense mechanisms against attacks)
add_executable(test_defense_resilience src/test_defense_resilience.cpp)
target_include_directories(test_defense_resilience PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_defense_resilience oqs)
    target_compile_definitions(test_defense_resilience PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_defense_resilience OpenSSL::Crypto)
        target_compile_definitions(test_defense_resilience PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_defense_resilience ${SODIUM_LIBRARIES})
    target_compile_definitions(test_defense_resilience PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(test_defense_resilience pthread)
create_launcher(test_defense_resilience)

# Defense Resilience Test - Paper Data Collection (1000+ samples for paper)
add_executable(test_defense_paper src/test_defense_paper.cpp)
target_include_directories(test_defense_paper PRIVATE ${CMAKE_SOURCE_DIR})
if(liboqs_FOUND)
    target_link_libraries(test_defense_paper oqs)
    target_compile_definitions(test_defense_paper PRIVATE USE_LIBOQS)
    if(OPENSSL_FOUND)
        target_link_libraries(test_defense_paper OpenSSL::Crypto)
        target_compile_definitions(test_defense_paper PRIVATE USE_OPENSSL_SHA3)
    endif()
endif()
if(SODIUM_FOUND)
    target_link_libraries(test_defense_paper ${SODIUM_LIBRARIES})
    target_compile_definitions(test_defense_paper PRIVATE USE_LIBSODIUM)
endif()
target_link_libraries(test_defense_paper pthread)
create_launcher(test_defense_paper)
