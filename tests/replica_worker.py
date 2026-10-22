"""
A second gateway process for the two-process budget test (T27, S-13).

Run by the test with the suite's environment inherited: it builds the
gateway's own settings and engine, verifies each context it is given with the
shipped verifier, and runs the shipped reservation transaction for each —
in a few threads, so its transactions race the other process's on the one
shared database. Prints one JSON line: the outcome counts.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor

import auth_sdk_m8.utils.paths as _paths

# The suite's environment is complete; there is no .env to find.
_paths.find_dotenv = lambda *_a, **_kw: ""

from ai_sdk_m8.schemas import Capability, EmbedRequest  # noqa: E402

from ai_gateway.core import deps  # noqa: E402
from ai_gateway.core.errors import GatewayError  # noqa: E402
from ai_gateway.execution.jobs import EmbedJob  # noqa: E402
from ai_gateway.execution.limits import ExecutionLimits  # noqa: E402
from ai_gateway.execution.reservation import reserve  # noqa: E402
from ai_gateway.controllers.resolution import ResolutionPolicy  # noqa: E402


def main() -> int:
    job_input = json.loads(sys.stdin.read())
    budget = int(job_input["budget"])
    limits = ExecutionLimits(client_daily_units=budget)
    policy = ResolutionPolicy.from_settings(deps.settings)
    job = EmbedJob(
        EmbedRequest(
            profile_key=job_input["profile_key"], inputs=tuple(job_input["inputs"])
        )
    )

    def one(token: str) -> str:
        principal = deps.job_contexts.verify(
            token, presenter=job_input["presenter"], capability=Capability.EMBEDDING
        )
        try:
            reserve(deps.db_engine, principal, job, policy=policy, limits=limits)
        except GatewayError as error:
            return error.code.value
        return "reserved"

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(one, job_input["tokens"]))
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome] = counts.get(outcome, 0) + 1
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
