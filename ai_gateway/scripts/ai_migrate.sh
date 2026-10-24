#!/bin/sh
# The ai-migrate one-shot: the only command that executes Alembic. Run it with
# the schema-owner role's credentials, before the web and scheduler start.
# It applies the migrations packaged in this image and never autogenerates,
# then records (or verifies) the installation identity, AI_DEPLOYMENT_ID.
set -e

export PYTHONPATH=/opt

alembic -c /opt/ai_gateway/alembic.ini upgrade head
exec python -m ai_gateway.installation init
