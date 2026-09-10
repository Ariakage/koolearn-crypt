#!/usr/bin/env bash
# 构建 x86_64 oracle harness（需 Rosetta 可运行 x86_64）
set -euo pipefail
cd "$(dirname "$0")"

clang -arch x86_64 -O1 -Wall -o oracle oracle.c -ldl
echo "built: $(pwd)/oracle"
file oracle | sed 's/^/  /'
