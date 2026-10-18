#!/bin/sh
# Web run-mode. Waits for the database and refuses to start unless the
# database revision equals the packaged head. It never migrates: schema
# changes run only through the ai-migrate one-shot (scripts/ai_migrate.sh).
set -e

if ! ./ai_gateway/scripts/pre_start.sh; then
    echo "Pre-start checks failed"
    exit 1
fi

if [ "$VSCODE_DEBUG" = "true" ]; then
  echo "Starting ai_gateway under VS Code debugpy..."
  exec python -m debugpy \
    --listen 0.0.0.0:5678 \
    --wait-for-client \
    -m uvicorn ai_gateway.main:app \
      --host 0.0.0.0 --port 8000 --reload
else
  exec uvicorn ai_gateway.main:app --host 0.0.0.0 --port 8000
fi
