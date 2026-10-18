#!/bin/sh
# Shared pre-start checks: database wait, then the read-only schema-revision
# check against the packaged head. No migration, no autogenerate.
set -e

export PYTHONPATH=/opt

python -m ai_gateway.prestart || { echo "Pre-start checks failed"; exit 1; }
