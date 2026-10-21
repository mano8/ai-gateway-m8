"""
Execution routes — provider calls authorized by a signed job context.

The router is built by :func:`ai_gateway.core.execution_guard.build_execution_router`,
so every route added here inherits the mandatory service-client and
job-context dependency. Its prefix is the SDK route table's ``v1/execute``;
each route's capability comes from that table. No route is defined yet.
"""

from ai_gateway.core.execution_guard import build_execution_router

router = build_execution_router(prefix="/v1/execute", tags=["execution"])
