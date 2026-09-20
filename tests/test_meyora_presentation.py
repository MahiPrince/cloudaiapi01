import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meyora_core import CORE_VERSION, CoreRoute, _evidence_summary


def main():
    route = CoreRoute(
        action="reroute",
        route="read",
        target_model="gpt-5.6-luna",
        reasoning_effort="low",
        needs_web=False,
        needs_write=False,
        requires_confirmation=False,
        presentation_mode="concise",
        routing_note="Customer feedback summary.",
        answer=None,
    )
    assert route.presentation_mode == "concise"

    summary = _evidence_summary([
        {"tool": "mail_search", "ok": True, "count": 0},
        {"tool": "mail_search", "ok": True, "count": 10},
        {"tool": "mail_search", "ok": True, "count": 4},
        {"tool": "teams_search", "ok": False, "count": 8},
        {"tool": "work_context", "ok": True, "count": None},
    ])
    assert summary == "Based on 10 Outlook emails."
    assert _evidence_summary([{"tool": "mail_search", "ok": True, "count": 0}]) is None

    print(json.dumps({
        "ok": True,
        "version": CORE_VERSION,
        "presentation_mode": route.presentation_mode,
        "evidence_summary": summary,
        "empty_results_suppressed": True,
    }))


if __name__ == "__main__":
    main()
