#!/bin/sh
# Scheduler run-mode. Same pre-start checks as the web run-mode, and the same
# rule: it never migrates.
set -e

if ! ./ai_gateway/scripts/pre_start.sh; then
    echo "Pre-start checks failed"
    exit 1
fi

exec python -m ai_gateway.scheduler
