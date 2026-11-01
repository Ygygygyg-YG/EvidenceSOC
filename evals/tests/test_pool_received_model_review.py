"""Mirror the unchanged native received-response identity boundary."""

import pytest


def test_known_failed_attempt_before_matching_received_response():
    from evals import timing_pool

    expected = {"response_model": "deepseek-flash", "fingerprint": "expected"}
    received = {
        "http_status": 200,
        "raw_response": {"model": "deepseek-flash", "system_fingerprint": "expected"},
        "response_model": "deepseek-flash",
        "system_fingerprint": "expected",
    }
    assert (
        timing_pool.validate_received_models(
            [{"http_status": 503, "raw_response": None}, received], expected
        )
        == 1
    )


@pytest.mark.parametrize(
    "calls",
    [
        [{"http_status": 503, "raw_response": None}],
        [{"http_status": 200, "raw_response": None}],
        [{"http_status": 503, "raw_response": {"error": "unavailable"}}],
        [
            {
                "http_status": 200,
                "raw_response": {
                    "model": "different",
                    "system_fingerprint": "expected",
                },
                "response_model": "different",
                "system_fingerprint": "expected",
            }
        ],
    ],
)
def test_missing_or_different_received_identity_remains_refused(calls):
    from evals import timing_pool

    with pytest.raises(PermissionError):
        timing_pool.validate_received_models(
            calls, {"response_model": "deepseek-flash", "fingerprint": "expected"}
        )
