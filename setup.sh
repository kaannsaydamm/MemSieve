#!/bin/bash
set -e

echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing dependencies..."
pip install -r requirements.txt

echo "[*] Building C++ Tracer..."
mkdir -p build
# Check if cmake is available
if command -v cmake &> /dev/null; then
    cd build
    cmake ..
    make
    cd ..
else
    echo "[!] CMake not found, falling back to direct g++ compilation..."
    g++ -std=c++17 -o build/tracer src/main.cpp src/tracer.cpp
fi

echo "[*] Building vulnerable app for testing..."
gcc -fno-stack-protector -z execstack -o tests/vulnerable_app tests/vulnerable_app.c
gcc -fno-stack-protector -z execstack -o tests/mem_vault tests/mem_vault.c

echo "[+] Setup complete!"
echo "To run:"
echo "  source venv/bin/activate"
echo "  python3 memsieve.py --target ./vulnerable_app"
