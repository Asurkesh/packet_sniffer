#!/bin/bash
# Проверка запуска без прав root

./sniffer 2> output.log
if grep -q "requires root" output.log; then
    echo "Test passed: root check"
    exit 0
else
    echo "Test failed: no root warning"
    exit 1
fi