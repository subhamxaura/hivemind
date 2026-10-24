"""Deterministic correlation engine for incident investigation.

Auditable, rule-based correlation of telemetry signals, deployment changes,
and topology dependencies without black-box inferences or network calls.
"""

from datetime import datetime, timedelta

from hivemind.models import (
    AnalysisStatus,
    AnomalySignal,
    CandidateCause,
    DeploymentChange,
    EvidenceReference,
    IncidentAnalysisReport,
    IncidentEvent,
    LogExcerpt,
)
from hivemind.proposal import RemediationProposalGenerator

# Threshold above which a candidate may yield DIAGNOSED if not contested
DIAGNOSIS_SCORE_THRESHOLD = 0.60
COMPETITIVE_MARGIN_THRESHOLD = 0.15


class DeterministicCorrelationEngine:
    """Evaluates structured incident evidence against explicit, documented rules."""

    def __init__(self, incident: IncidentEvent):
        self.incident = incident
        self.window_end: datetime = incident.detection_timestamp
        self.window_start: datetime = self.window_end - timedelta(
            minutes=incident.analysis_window_minutes
        )

        # Pre-index records for fast and exact citation lookups
        self.signals_by_id: dict[str, AnomalySignal] = {s.signal_id: s for s in incident.signals}
        self.changes_by_id: dict[str, DeploymentChange] = {c.change_id: c for c in incident.changes}
        self.logs_by_id: dict[str, LogExcerpt] = {item.log_id: item for item in incident.log_excerpts}

        # Filter records strictly within analysis window [window_start, window_end]
        self.window_signals: list[AnomalySignal] = [
            s for s in incident.signals if self.window_start <= s.timestamp <= self.window_end
        ]
        self.window_changes: list[DeploymentChange] = [
            c for c in incident.changes if self.window_start <= c.timestamp <= self.window_end
        ]
        self.window_logs: list[LogExcerpt] = [
            item for item in incident.log_excerpts if self.window_start <= item.timestamp <= self.window_end
        ]

    def analyze(self) -> IncidentAnalysisReport:
        """Runs the deterministic correlation pipeline and produces an auditable report."""
        candidates: list[CandidateCause] = []
        inconclusive_reasons: list[str] = []

        # 1. Rule Evaluation: Recent Deployment / Config Changes on affected services
        change_candidates = self._evaluate_change_candidates()
        candidates.extend(change_candidates)

        # 2. Rule Evaluation: Cascading Dependency Failures
        dependency_candidates = self._evaluate_dependency_candidates()
        candidates.extend(dependency_candidates)

        # 3. Assess missing telemetry/evidence across affected services
        missing_reasons = self._assess_missing_evidence()

        # 4. Sort candidates by evidence score descending
        candidates.sort(key=lambda c: c.evidence_score, reverse=True)

        # 5. Determine overall diagnostic status and audit outcome
        status = AnalysisStatus.INCONCLUSIVE
        failure_reasons: list[str] = []
        summary: str

        if not candidates:
            failure_reasons.append("No plausible candidate causes identified from provided evidence.")
            summary = "Investigation yielded no strong candidate root cause due to absence of correlating events."
        elif candidates[0].evidence_score < DIAGNOSIS_SCORE_THRESHOLD:
            failure_reasons.append(
                f"Top candidate '{candidates[0].title}' score ({candidates[0].evidence_score:.2f}) "
                f"is below the deterministic threshold ({DIAGNOSIS_SCORE_THRESHOLD:.2f})."
            )
            summary = (
                f"Investigation inconclusive: Highest evidence score ({candidates[0].evidence_score:.2f}) "
                f"for candidate '{candidates[0].title}' lacks sufficient evidence."
            )
        elif len(candidates) > 1 and (candidates[0].evidence_score - candidates[1].evidence_score) < COMPETITIVE_MARGIN_THRESHOLD:
            failure_reasons.append(
                f"Competing candidates '{candidates[0].title}' ({candidates[0].evidence_score:.2f}) and "
                f"'{candidates[1].title}' ({candidates[1].evidence_score:.2f}) differ by less than "
                f"margin threshold ({COMPETITIVE_MARGIN_THRESHOLD:.2f}); competing evidence cannot be resolved deterministically."
            )
            summary = (
                f"Investigation inconclusive due to competing hypotheses: '{candidates[0].title}' vs "
                f"'{candidates[1].title}'."
            )
        else:
            top = candidates[0]
            if top.contradicting_evidence:
                failure_reasons.append(
                    f"Top candidate '{top.title}' has unresolved contradicting evidence records."
                )
                summary = (
                    f"Investigation inconclusive: Contradictory evidence exists against primary candidate "
                    f"'{top.title}'."
                )
            else:
                status = AnalysisStatus.DIAGNOSED
                summary = (
                    f"Diagnosed with evidence score {top.evidence_score:.2f}: {top.title}. "
                    f"Supported by {len(top.supporting_evidence)} direct evidence citations."
                )

        if status == AnalysisStatus.DIAGNOSED:
            inconclusive_reasons = []
            telemetry_warnings = missing_reasons
        else:
            inconclusive_reasons = missing_reasons + failure_reasons
            telemetry_warnings = []

        # 6. Generate proposal if diagnosed
        proposal = None
        if status == AnalysisStatus.DIAGNOSED and candidates:
            proposal = RemediationProposalGenerator.generate(self.incident, candidates[0])

        return IncidentAnalysisReport(
            incident_id=self.incident.incident_id,
            environment=self.incident.environment,
            status=status,
            summary=summary,
            analysis_window_start=self.window_start,
            analysis_window_end=self.window_end,
            ranked_candidates=candidates,
            proposal=proposal,
            inconclusive_reasons=inconclusive_reasons,
            telemetry_warnings=telemetry_warnings,
        )

    def _evaluate_change_candidates(self) -> list[CandidateCause]:
        """Evaluates whether recent deployment/config changes correlated with anomalies."""
        results: list[CandidateCause] = []

        for change in self.window_changes:
            if change.service not in self.incident.affected_services:
                continue

            # Identify signals on this service
            svc_signals = [s for s in self.window_signals if s.service == change.service]
            if not svc_signals:
                continue

            # Earliest anomaly signal on this service
            earliest_signal = min(svc_signals, key=lambda s: s.timestamp)

            breakdown: dict[str, float] = {}
            supporting: list[EvidenceReference] = []
            contradicting: list[EvidenceReference] = []
            missing: list[str] = []

            # Supporting change citation
            supporting.append(
                EvidenceReference(
                    record_type="change",
                    record_id=change.change_id,
                    summary=f"{change.change_type} applied to {change.service} (identifier: {change.identifier})",
                )
            )

            # Check temporal ordering: Did the change occur BEFORE the earliest anomaly signal?
            if change.timestamp > earliest_signal.timestamp:
                # Contradiction: change occurred AFTER the anomaly began!
                contradicting.append(
                    EvidenceReference(
                        record_type="signal",
                        record_id=earliest_signal.signal_id,
                        summary=(
                            f"Anomaly '{earliest_signal.name}' began at {earliest_signal.timestamp.isoformat()}, "
                            f"which is before change was applied at {change.timestamp.isoformat()}"
                        ),
                    )
                )
                breakdown["temporal_sequence_violation_penalty"] = -0.40
            else:
                breakdown["base_change_relevance"] = 0.40

                # Proximity bonus: Change applied within 15 minutes before the anomaly
                delta_minutes = (earliest_signal.timestamp - change.timestamp).total_seconds() / 60.0
                if delta_minutes <= 15.0:
                    breakdown["temporal_proximity_bonus"] = 0.20
                elif delta_minutes <= 30.0:
                    breakdown["temporal_proximity_bonus"] = 0.10

            # Correlate specific signal types with change details
            has_matching_signature = False
            for sig in svc_signals:
                supporting.append(
                    EvidenceReference(
                        record_type="signal",
                        record_id=sig.signal_id,
                        summary=f"{sig.severity.upper()} signal '{sig.name}' observed with value {sig.value}",
                    )
                )

                # Signature matching
                sig_name = sig.name.lower()
                details = change.details

                # Match 1: OOMKilled / Restart following memory limit change
                if ("oom" in sig_name or "restart" in sig_name) and (
                    "memory" in details or "memory_limit" in details or change.change_type == "resource_limit"
                ):
                    has_matching_signature = True

                # Match 2: CrashLoopBackOff or HTTP error rate spike following deployment
                if ("crash" in sig_name or "error_rate" in sig_name or "5xx" in sig_name) and (
                    change.change_type == "deployment" or "image" in details
                ):
                    has_matching_signature = True

            if has_matching_signature:
                breakdown["signature_match_bonus"] = 0.25

            # Correlate logs on this service
            svc_logs = [entry for entry in self.window_logs if entry.service == change.service]
            for log in svc_logs:
                msg_lower = log.message.lower()
                if any(k in msg_lower for k in ["error", "exception", "fatal", "oom", "killed", "panic", "crash"]):
                    supporting.append(
                        EvidenceReference(
                            record_type="log",
                            record_id=log.log_id,
                            summary=f"Error log on {change.service}: {log.message[:80]}...",
                        )
                    )
                    breakdown["log_corroboration_bonus"] = 0.10
                    break

            if not change.prior_known_good_identifier:
                missing.append("Prior known-good identifier not specified in change event.")

            # Compute normalized score [0.0, 1.0]
            raw_score = sum(breakdown.values())
            score = max(0.0, min(1.0, round(raw_score, 2)))

            rationale = (
                f"Change {change.identifier} on {change.service} occurred at {change.timestamp.isoformat()}, "
                f"followed by {len(svc_signals)} anomaly signal(s) on the same service."
            )
            uncertainty = (
                "Correlation is deterministic based on temporal proximity and metric signature. "
                "Causality cannot be proven without deeper application runtime tracing."
            )

            results.append(
                CandidateCause(
                    candidate_id=f"cause-change-{change.change_id}",
                    title=f"Faulty Change on {change.service} ({change.identifier})",
                    description=(
                        f"Recent {change.change_type} ({change.identifier}) on {change.service} directly "
                        f"preceded anomaly signals."
                    ),
                    evidence_score=score,
                    scoring_breakdown=breakdown,
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    rationale=rationale,
                    uncertainty=uncertainty,
                    missing_evidence=missing,
                )
            )

        return results

    def _evaluate_dependency_candidates(self) -> list[CandidateCause]:
        """Evaluates whether failure originated in an upstream or downstream dependency."""
        results: list[CandidateCause] = []

        for dep in self.incident.dependencies:
            if dep.source_service not in self.incident.affected_services:
                continue

            target_svc = dep.target_service
            # Check signals reported for target_service
            target_signals = [s for s in self.window_signals if s.service == target_svc]

            # Check if there is an explicit healthy signal contradicting failure
            healthy_signals = [
                s for s in target_signals
                if "health" in s.name.lower() and str(s.value).lower() in ["healthy", "ok", "up", "200", "0"]
            ]
            anomaly_target_signals = [
                s for s in target_signals
                if s not in healthy_signals and s.severity in ["warning", "critical"]
            ]

            if not anomaly_target_signals and not healthy_signals:
                continue

            breakdown: dict[str, float] = {}
            supporting: list[EvidenceReference] = []
            contradicting: list[EvidenceReference] = []
            missing: list[str] = []

            if anomaly_target_signals:
                breakdown["base_dependency_signal"] = 0.35
                for sig in anomaly_target_signals:
                    supporting.append(
                        EvidenceReference(
                            record_type="signal",
                            record_id=sig.signal_id,
                            summary=f"Dependency {target_svc} reported {sig.severity} anomaly: {sig.name}={sig.value}",
                        )
                    )

                if dep.critical:
                    breakdown["critical_dependency_weight"] = 0.25

                # Check if dependency anomaly preceded source service anomalies
                source_signals = [s for s in self.window_signals if s.service == dep.source_service]
                if source_signals:
                    earliest_source = min(source_signals, key=lambda s: s.timestamp)
                    earliest_target = min(anomaly_target_signals, key=lambda s: s.timestamp)
                    if earliest_target.timestamp <= earliest_source.timestamp:
                        breakdown["temporal_precedence_bonus"] = 0.20
                        supporting.append(
                            EvidenceReference(
                                record_type="signal",
                                record_id=earliest_target.signal_id,
                                summary=(
                                    f"Dependency {target_svc} anomaly preceded {dep.source_service} "
                                    f"anomaly by {(earliest_source.timestamp - earliest_target.timestamp).total_seconds():.0f}s"
                                ),
                            )
                        )

            # Check for contradicting healthy telemetry
            if healthy_signals:
                for h_sig in healthy_signals:
                    contradicting.append(
                        EvidenceReference(
                            record_type="signal",
                            record_id=h_sig.signal_id,
                            summary=f"Dependency {target_svc} reported healthy status: {h_sig.name}={h_sig.value}",
                        )
                    )
                breakdown["healthy_telemetry_contradiction_penalty"] = -0.35

            # Correlate client logs mentioning downstream service
            source_logs = [entry for entry in self.window_logs if entry.service == dep.source_service]
            for log in source_logs:
                if target_svc.lower() in log.message.lower():
                    supporting.append(
                        EvidenceReference(
                            record_type="log",
                            record_id=log.log_id,
                            summary=f"Source service log references {target_svc}: {log.message[:80]}...",
                        )
                    )
                    breakdown["client_log_correlation_bonus"] = 0.10
                    break

            raw_score = sum(breakdown.values())
            score = max(0.0, min(1.0, round(raw_score, 2)))

            rationale = (
                f"{dep.source_service} depends on {target_svc} ({dep.dependency_type}). "
                f"{len(anomaly_target_signals)} anomaly signal(s) observed on {target_svc}."
            )
            uncertainty = (
                f"Dependency health is based on reported telemetry for {target_svc}. "
                "Network partition or client-side connection pooling issues may also contribute."
            )

            results.append(
                CandidateCause(
                    candidate_id=f"cause-dep-{dep.source_service}-to-{target_svc}",
                    title=f"Dependency Degradation: {target_svc}",
                    description=(
                        f"Cascading failure originating from {target_svc}, which is a "
                        f"{'critical ' if dep.critical else ''}dependency of {dep.source_service}."
                    ),
                    evidence_score=score,
                    scoring_breakdown=breakdown,
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    rationale=rationale,
                    uncertainty=uncertainty,
                    missing_evidence=missing,
                )
            )

        return results

    def _assess_missing_evidence(self) -> list[str]:
        """Identifies gaps in provided telemetry that prevent deterministic confidence."""
        missing: list[str] = []

        if not self.window_changes:
            missing.append("No deployment or configuration change records provided within the analysis window.")

        if not self.window_signals:
            missing.append("No telemetry anomaly signals observed within the analysis window.")

        # Check declared dependencies without any telemetry signals
        declared_targets = {dep.target_service for dep in self.incident.dependencies}
        services_with_signals = {s.service for s in self.window_signals}
        unmonitored_deps = declared_targets - services_with_signals
        if unmonitored_deps:
            missing.append(
                f"Telemetry missing for declared dependencies: {', '.join(sorted(unmonitored_deps))}."
            )

        if not self.window_logs:
            missing.append("No log excerpts provided in analysis window.")

        return missing
