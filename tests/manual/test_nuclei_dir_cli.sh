#!/bin/bash

TARGET="http://localhost:4280"
BASE_DIR="/home/bbb/nuclei-templates/dast/vulnerabilities/lfi"

echo "1. Testing directory with trailing slash AND -dast:"
nuclei -t "$BASE_DIR/" -u "$TARGET" -silent -dast
echo "Exit Code: $?"

echo "2. Testing directory without trailing slash:"
nuclei -t "$BASE_DIR" -u "$TARGET" -silent
echo "Exit Code: $?"

echo "3. Testing wildcard *.yaml:"
nuclei -t "$BASE_DIR/*.yaml" -u "$TARGET" -silent
echo "Exit Code: $?"

echo "4. Testing single file WITH -dast:"
nuclei -t "$BASE_DIR/linux-lfi-fuzz.yaml" -u "$TARGET" -silent -dast
echo "Exit Code: $?"
