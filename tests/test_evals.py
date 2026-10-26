"""Tests for evaluation suite and agent invariants (D15)."""

from __future__ import annotations

import pytest

from src.evals.eval_suite import (
    evaluate_vulnerability_detection,
    verify_hitl_approval_invariant,
    verify_retry_cap_invariant,
)


class TestEvalSuite:
    """Test vulnerability detection evaluation, precision/recall, and invariant verification."""

    def test_synthetic_vulnerability_detection_metrics(self) -> None:
        metrics = evaluate_vulnerability_detection()
        assert metrics.total_test_cases >= 5
        assert metrics.precision > 0.0
        assert metrics.recall > 0.0
        assert metrics.f1_score > 0.0
        assert metrics.true_positives > 0

    def test_retry_cap_invariant_enforced(self) -> None:
        result = verify_retry_cap_invariant(max_allowed_retries=2)
        assert result["terminated_cleanly"] is True
        assert result["actual_retries"] == 2
        assert len(result["history"]) == 2

    def test_hitl_approval_gate_invariant_enforced(self) -> None:
        result = verify_hitl_approval_invariant()
        assert result["invariant_passed"] is True
        assert result["is_breaking"] is True
        assert result["triggers_hitl_interrupt"] is True
