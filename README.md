# MeshChain V2X Blockchain Simulation

A witness-linked mesh blockchain implementation for vehicular networks with post-quantum cryptography and real-time accountability.

## Overview

MeshChain is a distributed blockchain system designed for Vehicle-to-Everything (V2X) communication networks. It implements a witness-based consensus mechanism with post-quantum cryptographic primitives to ensure security against both classical and quantum attacks.

## Core Features

### Cryptography
- FALCON-512 signatures for vehicle authentication
- ML-KEM-768 for key encapsulation
- Dilithium-3 for RSU signatures
- XChaCha20-Poly1305 AEAD encryption
- Time-of-Flight distance bounding (sub-10ns tolerance)

### Network Integration
- SUMO traffic simulator integration via TraCI
- WAVE (IEEE 802.11p) V2V/V2I communication
- OMNeT++ and Veins support for realistic wireless simulation
- libp2p for distributed networking (DHT, GossipSub, Bitswap)

### Blockchain Architecture
- Witness diversity enforcement (OEM, spatial, temporal, reputation)
- Multi-tier anchoring (L1/L2/L3) via RSUs
- TEE-based attestquorum protocol
- Off-chain storage with Shamir secret sharing
- Local finality under 100ms

### Attack Resistance Directly
- Defense against witness collusion (T1)
- Protection from replay attacks (T2)
- Mitigation of Sybil attacks (T3)
- Silent witness detection (T6)

## System Requirements

### Required Dependencies
- CMake 3.15+
- C++17 compiler (GCC 7+, Clang 5+)
- liboqs (post-quantum cryptography)
- libsodium (AEAD encryption)
- OpenSSL 1.1+ (SHA3-256)

### Optional Dependencies
- SUMO 1.15+ (traffic simulation)
- OMNeT++ 6.0+ with Veins (realistic wireless)
- ns-3 (alternative WAVE simulation)

## Building

```bash
# Configure build
cmake -B build -DALLOW_SIMULATION_MODE=ON

# Compile
cmake --build build -j$(nproc)

# Executables generated in build/ directory
```

## Running Simulations

### Basic Simulation
```bash
cd build
./meshchain_integrated --vehicles 20 --duration 180
```

### Rural Scenario (300 vehicles)
```bash
cd build
./meshchain_rural
```

### Attack Scenario Testing
```bash
cd build
./meshchain_integrated_attack --attack-mode T1 --beta 0.2
```

## Configuration

Configuration files are located in `config/` directory:
- `simulation_config.yaml` - Standard highway scenario
- `rural_simulation_config.yaml` - Large-scale rural scenario (300 vehicles)

Key parameters:
- Vehicle count and spawn interval
- RSU count and anchor periods
- Witness selection profiles (3/2, 5/3, 7/5)
- Diversity policy thresholds
- WAVE and ToF parameters

## Architecture

### Components

**Vehicle Node**
- Micro-chain maintenance
- Witness selection with diversity enforcement
- Block creation and validation
- WAVE message handling

**RSU (Roadside Unit)**
- L1 anchor creation (vehicle block aggregation)
- L2 anchor creation (cross-RSU synchronization)
- L3 anchor creation (global checkpoints)
- Merkle proof generation

**Integrated Vehicle**
- TraCI client for SUMO mobility
- WAVE stack for V2V/V2I communication
- ToF adapter for distance verification
- libp2p node for P2P networking

### Block Structure

Each block contains:
- Header with state, timestamp, creator ID
- Witness bitmap and attestquorum signature
- Transaction payload (V2X communication logs)
- Merkle roots for witness and transaction verification

## Testing

```bash
# Cryptography verification
cd build
./verify_crypto

# FALCON signature test
./test_falcon_verification

# Defense mechanism test
./test_defense_paper

# ZKP/STARK system test
./test_zkp
```

## Performance Targets

- Local finality: Under 100ms
- Block size: Under 10KB
- Signature bandwidth: Under 50 KB/s
- Scalability: 300+ concurrent vehicles

## Directory Structure

```
meshchain_sim_tls_scale/
├── src/                    # Source code
│   ├── common/            # Common types and utilities
│   ├── crypto/            # Cryptographic primitives
│   ├── vehicle/           # Vehicle node implementation
│   ├── infrastructure/    # RSU and anchoring
│   ├── integration/       # SUMO, WAVE, ToF adapters
│   ├── network/           # P2P and OMNeT++ integration
│   ├── storage/           # Off-chain storage
│   └── security/          # Attack models
├── config/                # Configuration files
└── sumo/                  # SUMO scenarios

```

## License

This is research software. See LICENSE file for details.

## Citation

If you use this software in your research, please cite the corresponding paper.
