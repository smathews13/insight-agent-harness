"""Evidence-bound answer validation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Answer, AnswerBlockKind, evidence_by_id

_QUANTITY = re.compile(r"(?<![A-Za-z0-9_])(?:[$€£]\s*)?-?\d+(?:[,\d]*)(?:\.\d+)?(?:\s*%)?")


@dataclass(frozen=True)
class AnswerValidationIssue:
    code: str
    message: str
    block_id: str = ""


@dataclass(frozen=True)
class AnswerValidation:
    issues: tuple[AnswerValidationIssue, ...]

    @property
    def valid(self) -> bool:
        return not self.issues

    def raise_for_errors(self) -> None:
        if self.issues:
            raise ValueError("; ".join(f"{issue.code}: {issue.message}" for issue in self.issues))


class QuantitativeAnswerValidator:
    """Requires explicit evidence for every quantitative answer block.

    This validates binding and completeness, not the semantic correctness of a
    metric. A scorer or provider-specific evaluator must perform that separate
    check.
    """

    def validate(self, answer: Answer) -> AnswerValidation:
        issues = []
        try:
            indexed_evidence = evidence_by_id(answer.evidence)
        except ValueError as exc:
            issues.append(AnswerValidationIssue("duplicate_evidence_id", str(exc)))
            indexed_evidence = {evidence.evidence_id: evidence for evidence in answer.evidence}

        quantitative_tokens = set()
        for block in answer.blocks:
            unknown = [
                reference for reference in block.evidence_refs if reference not in indexed_evidence
            ]
            if unknown:
                issues.append(
                    AnswerValidationIssue(
                        "unknown_evidence_ref",
                        "unknown evidence: {}".format(", ".join(sorted(unknown))),
                        block.block_id,
                    )
                )
            if block.kind is not AnswerBlockKind.QUANTITATIVE:
                continue
            if not block.evidence_refs:
                issues.append(
                    AnswerValidationIssue(
                        "quantitative_evidence_required",
                        "quantitative content must name at least one evidence reference",
                        block.block_id,
                    )
                )
            tokens = set(_QUANTITY.findall(block.content))
            if not tokens:
                issues.append(
                    AnswerValidationIssue(
                        "quantitative_value_required",
                        "quantitative content must contain a numeric value",
                        block.block_id,
                    )
                )
            quantitative_tokens.update(tokens)

        summary_tokens = set(_QUANTITY.findall(answer.summary))
        unbound_summary_tokens = summary_tokens - quantitative_tokens
        if unbound_summary_tokens:
            issues.append(
                AnswerValidationIssue(
                    "unbound_summary_quantity",
                    "summary quantities must also appear in an evidence-bound "
                    "quantitative block: {}".format(", ".join(sorted(unbound_summary_tokens))),
                )
            )

        return AnswerValidation(tuple(issues))
