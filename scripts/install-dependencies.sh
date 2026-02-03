#!/bin/bash

# Mesh-Chain 의존성 자동 설치 스크립트
# SUMO + cpp-libp2p 설치

set -e  # 에러 시 중단

echo "=================================================="
echo "  Mesh-Chain 의존성 자동 설치"
echo "=================================================="
echo ""
echo "설치할 구성 요소:"
echo "  1. SUMO (교통 시뮬레이션)"
echo "  2. cpp-libp2p (P2P 네트워킹)"
echo ""
echo "예상 소요 시간: 30-60분"
echo "디스크 공간: ~2GB"
echo ""

read -p "계속하시겠습니까? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "설치 취소됨."
    exit 1
fi

# 작업 디렉토리
WORK_DIR="$HOME/meshchain-deps"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo ""
echo "=================================================="
echo "  1/2: SUMO 설치"
echo "=================================================="
echo ""

# SUMO 이미 설치 확인
if command -v sumo &> /dev/null; then
    echo "✓ SUMO가 이미 설치되어 있습니다."
    sumo --version
else
    echo "SUMO 설치 중..."

    # Ubuntu/Debian PPA 방식 (빠름)
    if [ -f /etc/debian_version ]; then
        echo "Ubuntu/Debian 감지 - PPA로 설치합니다..."

        sudo apt-get update
        sudo add-apt-repository -y ppa:sumo/stable
        sudo apt-get update
        sudo apt-get install -y sumo sumo-tools sumo-doc

        # 환경 변수 설정
        export SUMO_HOME="/usr/share/sumo"

        if ! grep -q "SUMO_HOME" ~/.bashrc; then
            echo 'export SUMO_HOME="/usr/share/sumo"' >> ~/.bashrc
            echo 'export PATH="$SUMO_HOME/bin:$PATH"' >> ~/.bashrc
        fi

        echo "✓ SUMO 설치 완료!"
        sumo --version
    else
        echo "❌ Ubuntu/Debian이 아닙니다. 수동 설치가 필요합니다."
        echo "   https://sumo.dlr.de/docs/Installing/index.html"
        exit 1
    fi
fi

echo ""
echo "=================================================="
echo "  2/2: cpp-libp2p 설치"
echo "=================================================="
echo ""

# cpp-libp2p 확인
if [ -f /usr/local/lib/libp2p.so ] || [ -f /usr/lib/libp2p.so ]; then
    echo "✓ cpp-libp2p가 이미 설치되어 있습니다."
else
    echo "cpp-libp2p 설치 중..."
    echo "⚠️  이 작업은 시간이 오래 걸립니다 (20-40분)..."

    # 의존성 설치
    echo "의존성 설치 중..."
    sudo apt-get install -y \
        build-essential cmake git \
        libssl-dev libboost-all-dev \
        libprotobuf-dev protobuf-compiler \
        pkg-config

    # cpp-libp2p 클론
    if [ ! -d "$WORK_DIR/cpp-libp2p" ]; then
        echo "cpp-libp2p 소스 다운로드 중..."
        git clone --recursive https://github.com/libp2p/cpp-libp2p.git
        cd cpp-libp2p
    else
        echo "기존 cpp-libp2p 디렉토리 사용"
        cd cpp-libp2p
    fi

    # 빌드
    echo "cpp-libp2p 빌드 중 (시간 소요: 20-40분)..."
    mkdir -p build
    cd build

    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DTESTING=OFF \
        -DEXAMPLES=OFF

    make -j$(nproc)

    # 설치
    echo "cpp-libp2p 설치 중..."
    sudo make install
    sudo ldconfig

    echo "✓ cpp-libp2p 설치 완료!"
fi

echo ""
echo "=================================================="
echo "  설치 완료!"
echo "=================================================="
echo ""
echo "설치된 구성 요소:"
echo ""

# SUMO 확인
if command -v sumo &> /dev/null; then
    echo "✓ SUMO: $(sumo --version 2>&1 | head -1)"
    echo "  SUMO_HOME: $SUMO_HOME"
else
    echo "✗ SUMO: 설치 실패"
fi

# cpp-libp2p 확인
if [ -f /usr/local/lib/libp2p.so ] || [ -f /usr/lib/libp2p.so ]; then
    echo "✓ cpp-libp2p: 설치됨"
    echo "  위치: /usr/local/lib"
else
    echo "⚠️  cpp-libp2p: 확인 불가 (선택사항)"
fi

echo ""
echo "다음 단계:"
echo "  1. 새 터미널을 열거나 'source ~/.bashrc' 실행"
echo "  2. cd ./build"
echo "  3. rm -rf * && cmake .."
echo "  4. make -j\$(nproc)"
echo "  5. ./meshchain_integrated --help"
echo ""
echo "설치 스크립트 완료!"
