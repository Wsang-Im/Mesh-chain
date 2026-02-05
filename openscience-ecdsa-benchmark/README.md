# ECDSA P-256 Signing Benchmark for OP-TEE on Cortex-A72

This repository contains the source code and benchmark results for measuring ECDSA P-256 signing performance in OP-TEE (Trusted Execution Environment) on ARM Cortex-A72.

## Overview

This benchmark measures the time required for ECDSA P-256 digital signature generation inside a TEE, specifically targeting the attestation protocol use case in V2X (Vehicle-to-Everything) communication systems.

### Use Case: TEE-based Attestation

The benchmark simulates two attestation operations:
- **attestdiv**: `SignTEE(Hash(W) || metrics)` - 48 bytes input
- **attestquorum**: `SignTEE(Hash(Header) || bitmap)` - 40 bytes input

Target: Complete signature generation in **< 5ms** on automotive-grade processors.

## Benchmark Results

### Test Environment

| Component | Version/Configuration |
|-----------|----------------------|
| CPU Emulation | ARM Cortex-A72 |
| QEMU | 8.0.0 |
| QEMU icount | `shift=0,align=off` |
| TF-A | v2.9 |
| OP-TEE OS | 4.0 |
| Memory | 1024 MB |

### Results (100 iterations average)

| Operation | Time (1GHz baseline) | Estimated @2GHz |
|-----------|---------------------|-----------------|
| Key Generation | 2,564 us | ~1.28 ms |
| attestdiv Sign | 2,900 us | ~1.45 ms |
| attestquorum Sign | 2,910 us | ~1.46 ms |

### Performance Improvement

| Configuration | Signing Time | Notes |
|--------------|--------------|-------|
| Baseline mbedTLS | ~29,000 us | Default configuration |
| **With MBEDTLS_ECP_NIST_OPTIM** | **~2,900 us** | NIST P-256 optimized |
| **Improvement** | **~10x** | |

## Key Optimization: MBEDTLS_ECP_NIST_OPTIM

The critical optimization is enabling `MBEDTLS_ECP_NIST_OPTIM` in OP-TEE's mbedTLS kernel configuration.

This optimization uses specialized modular reduction for the NIST P-256 prime:
```
p = 2^256 - 2^224 + 2^192 + 2^96 - 1
```

### Configuration Location

File: `optee_os/lib/libmbedtls/include/mbedtls_config_kernel.h`

```c
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_NIST_OPTIM       /* NIST P-256 optimized modular reduction */
#define MBEDTLS_ECDSA_C
```

## About QEMU icount Mode

### Why icount?

Standard QEMU emulation includes host CPU overhead, making timing measurements unreliable. The `-icount shift=0,align=off` option enables **instruction counting mode**:

- `shift=0`: 1 instruction = 1 nanosecond (virtual time)
- `align=off`: No synchronization with host wall-clock

This provides **deterministic, reproducible measurements** independent of host CPU performance.

### Clock Speed Estimation

The icount baseline assumes 1GHz (1 IPC). For actual hardware:

| Clock Speed | Estimated Signing Time |
|-------------|----------------------|
| 1.0 GHz (icount) | 2.9 ms |
| 1.5 GHz (RPi4) | ~1.9 ms |
| 1.8 GHz | ~1.6 ms |
| 2.0 GHz | ~1.45 ms |
| 2.5 GHz | ~1.16 ms |

Formula: `Actual Time = icount_time * (1GHz / actual_clock)`

### Limitations

icount mode does **NOT** simulate:
- CPU pipeline (superscalar, out-of-order)
- Cache hierarchy (L1/L2/L3)
- Memory latency
- Branch prediction

However, for **cryptographic operations** (mostly register operations with minimal memory access), icount predictions are reasonably accurate.

## Directory Structure

```
.
├── README.md                 # This file
├── ta/                       # Trusted Application source
│   ├── ecdsa_sign_ta.c      # TA implementation
│   ├── include/
│   │   └── ecdsa_sign_ta.h  # TA header
│   ├── Makefile
│   └── sub.mk
├── host/                     # Host application source
│   ├── main.c               # Host implementation
│   └── Makefile
├── scripts/                  # Benchmark scripts
│   └── run-benchmark.exp    # Expect script for automation
├── configs/                  # Configuration files
│   └── mbedtls_config_kernel.h.patch
└── results/                  # Benchmark results
    └── benchmark_output.txt
```

## Dependencies

### System Requirements

- Ubuntu 20.04/22.04 LTS (or compatible Linux distribution)
- At least 16GB RAM (for building OP-TEE)
- At least 50GB free disk space

### Install Build Dependencies

```bash
# Update package list
sudo apt-get update

# Install essential build tools
sudo apt-get install -y \
    build-essential \
    git \
    python3 \
    python3-pip \
    python3-pyelftools \
    python3-cryptography

# Install cross-compilation toolchain
sudo apt-get install -y \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu

# Install QEMU build dependencies
sudo apt-get install -y \
    libglib2.0-dev \
    libfdt-dev \
    libpixman-1-dev \
    zlib1g-dev \
    ninja-build \
    meson

# Install OP-TEE build dependencies
sudo apt-get install -y \
    device-tree-compiler \
    libssl-dev \
    uuid-dev

# Install automation tools
sudo apt-get install -y \
    expect \
    curl \
    wget

# Install repo tool (for OP-TEE)
mkdir -p ~/.bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.bin/repo
chmod a+x ~/.bin/repo
export PATH="${HOME}/.bin:${PATH}"
```

### Clone and Build OP-TEE

```bash
# Create working directory
mkdir -p ~/optee && cd ~/optee

# Initialize repo with OP-TEE manifest
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 4.0.0

# Sync all repositories
repo sync -j4

# Apply MBEDTLS_ECP_NIST_OPTIM optimization
# Edit optee_os/lib/libmbedtls/include/mbedtls_config_kernel.h
# Add: #define MBEDTLS_ECP_NIST_OPTIM

# Build everything
cd build
make -j$(nproc) toolchains
make -j$(nproc)
```

### Build This Benchmark

```bash
# Set environment variables
export TA_DEV_KIT_DIR=~/optee/optee_os/out/arm/export-ta_arm64
export TEEC_EXPORT=~/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr
export CROSS_COMPILE=aarch64-linux-gnu-

# Build TA
cd ta
make

# Build Host Application
cd ../host
make
```

### Install to Rootfs

```bash
# Copy TA to rootfs
cp ta/*.ta ~/optee/out-br/target/lib/optee_armtz/

# Copy host binary to rootfs
cp host/optee_example_ecdsa_sign ~/optee/out-br/target/usr/bin/

# Rebuild rootfs
cd ~/optee/build
make buildroot
```

## Running the Benchmark

### Using the Automation Script

```bash
export QEMU=~/optee/qemu/build/qemu-system-aarch64
export QEMU_DIR=~/optee/out/bin
./scripts/run-benchmark.exp
```

### Manual QEMU Command

```bash
qemu-system-aarch64 \
    -nographic \
    -serial mon:stdio \
    -smp 1 \
    -machine virt,secure=on,gic-version=3 \
    -cpu cortex-a72 \
    -m 1024 \
    -icount shift=0,align=off \
    -semihosting-config enable=on,target=native \
    -bios bl1.bin \
    -initrd rootfs.cpio.gz \
    -kernel Image
```

### Inside QEMU

```bash
# Login as root (no password)
buildroot login: root

# Run with 100 iterations
/usr/bin/optee_example_ecdsa_sign 100
```

## License

SPDX-License-Identifier: BSD-2-Clause

## Citation

If you use this benchmark in your research, please cite:

```bibtex
@misc{ecdsa_tee_benchmark,
  title={ECDSA P-256 Signing Benchmark for OP-TEE on Cortex-A72},
  year={2024},
  howpublished={\url{https://github.com/[repository]}}
}
```
