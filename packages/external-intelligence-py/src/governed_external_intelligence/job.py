"""Scheduled Jobs boundary without collection or Databricks implementations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .core import ClaimParser, ExternalIntelligenceIngestor, FetchEnvelope, IngestionResult


@dataclass(frozen=True)
class ScheduledRunReport:
    attempted: int
    normalized_claims: int
    quarantined_snapshots: int
    results: tuple[IngestionResult, ...]


class ScheduledIngestionJob:
    """Runs an offline batch supplied by a separately governed collector.

    A Lakeflow Job adapter may construct this class after reading policy and
    fetched bytes from governed storage. The class never performs network I/O.
    """

    def __init__(
        self,
        ingestor: ExternalIntelligenceIngestor,
        parsers: Mapping[str, ClaimParser],
    ) -> None:
        self._ingestor = ingestor
        self._parsers = dict(parsers)

    def run(self, inputs: Sequence[FetchEnvelope]) -> ScheduledRunReport:
        results = []
        for envelope in inputs:
            try:
                parser = self._parsers[envelope.source_id]
            except KeyError as exc:
                raise ValueError(
                    f"no reviewed parser is registered for source {envelope.source_id}"
                ) from exc
            results.append(self._ingestor.ingest(envelope, parser))
        return ScheduledRunReport(
            attempted=len(inputs),
            normalized_claims=sum(len(result.claims) for result in results),
            quarantined_snapshots=sum(result.quarantine is not None for result in results),
            results=tuple(results),
        )
