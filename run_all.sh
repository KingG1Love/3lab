#!/bin/bash
# Run all tasks for Lab 3
# Before running Task 2, set: export GITHUB_TOKEN=your_token

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==============================="
echo "  Lab 3 — Vulnerability Scan"
echo "==============================="

echo ""
echo "[1/3] Task 1: Collecting dependencies..."
python3 task1/task1_collect_deps.py

echo ""
echo "[2/3] Task 2: Checking vulnerabilities via GHSA..."
if [ -z "$GITHUB_TOKEN" ]; then
    echo "  WARNING: GITHUB_TOKEN not set. Set it with:"
    echo "    export GITHUB_TOKEN=ghp_token"
    echo "  Skipping Task 2."       
else
    python3 task2/task2_check_vulns.py
fi

echo ""
echo "[3/3] Task 3: Analyzing vulnerabilities..."
if [ -f task2/result_task_2.json ]; then
    python3 task3/task3_analyze.py
else
    echo "  Skipping Task 3 (result_task_2.json not found)"
fi

echo ""
echo "==============================="
echo "Tasks 4 and 5 must be run on openSUSE Leap 15.5:"
echo "  python3 task4/task4_inventory_os.py"
echo "  python3 task5/task5_osv_scan.py"
echo "==============================="
echo ""
echo "Done!"
