#!/bin/sh
cd "$(dirname "$0")" && python3 -m pytest backend/tests -v
