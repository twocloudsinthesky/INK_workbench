#!/bin/sh
cd "$(dirname "$0")" || exit 1
exec python3 '启动.py' --open
