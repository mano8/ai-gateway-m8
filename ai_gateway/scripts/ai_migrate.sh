#!/bin/sh
# The ai-migrate one-shot: the only command that executes Alembic. Run it with
# the schema-owner role's credentials, before the web and scheduler start.
# It applies the migrations packaged in this image and never autogenerates.
set -e

export PYTHONPATH=/opt

exec alembic -c /opt/ai_gateway/alembic.ini upgrade head
