#!/bin/bash
# run_all.sh — запуск задач 1-3 (задачи 4 и 5 запускать на openSUSE Leap 15.5)
# Usage: bash run_all.sh

set -e
cd "$(dirname "$0")"

echo "========================================"
echo "  Лабораторная №3 — Vulnerability Scan"
echo "========================================"

echo ""
echo "[1/3] Task 1: Сбор зависимостей..."
python3 task1_collect_deps.py --project ./spring-boot-main

echo ""
echo "[2/3] Task 2: Проверка уязвимостей через GHSA (async, ~15-20s)..."
if [ -z "$GITHUB_TOKEN" ]; then
    echo "  ВНИМАНИЕ: переменная GITHUB_TOKEN не задана."
    echo "  Задайте токен:"
    echo "    export GITHUB_TOKEN=ghp_ВАШ_ТОКЕН"
    echo "  Пропуск Task 2."
else
    python3 task2_check_vulns.py
fi

echo ""
echo "[3/3] Task 3: Анализ уязвимостей..."
if [ -f result_task_2.json ]; then
    python3 task3_analyze.py
else
    echo "  Пропуск: result_task_2.json не найден."
fi

echo ""
echo "========================================"
echo "Tasks 4 и 5 запускать на openSUSE Leap 15.5:"
echo "  python3 task4_inventory_os.py"
echo "  python3 task5_osv_scan.py"
echo ""
echo "После Task 5 — собрать архив для отправки:"
echo "  python3 pack_results.py"
echo "========================================"
