#!/bin/sh
# Scheduler run-mode (D-42). Same pre-start checks as the web run-mode, and the
# same rule: it never migrates. AI_RUN_MODE=scheduler is set here, not in the
# shared env file: this process neither needs nor reads the fingerprint key or
# the OCR receipt seed, which are mounted on the web service only.
set -e

export AI_RUN_MODE=scheduler

if ! ./ai_gateway/scripts/pre_start.sh; then
    echo "Pre-start checks failed"
    exit 1
fi

exec python -m ai_gateway.scheduler
