"""HiveMind Command Line Interface.

Provides human-reviewable terminal reports for incident telemetry and remediation proposals.
Strictly read-only: Never applies mutations to production.
"""

import sys
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from hivemind import __version__
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.models import IncidentAnalysisReport, IncidentEvent


def format_report_text(report: IncidentAnalysisReport) -> str:
    """Formats incident report into clear, human-readable terminal output."""
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(" HIVEMIND INCIDENT INVESTIGATION REPORT (READ-ONLY MVP)")
    lines.append(" Notice: No production changes were applied. Analysis is read-only.")
    lines.append("=" * 78)
    lines.append(f" Incident ID  : {report.incident_id}")
    lines.append(f" Environment  : {report.environment}")
    lines.append(f" Time Window  : {report.analysis_window_start.isoformat()} to {report.analysis_window_end.isoformat()}")

    status_tag = f"[{report.status.value}]"
    lines.append(f" Status       : {status_tag}")
    lines.append(f" Summary      : {report.summary}")
    lines.append("-" * 78)

    if report.inconclusive_reasons:
        lines.append(" INCONCLUSIVE AUDIT NOTES:")
        for reason in report.inconclusive_reasons:
            lines.append(f"   * {reason}")
        lines.append("-" * 78)

    lines.append(" RANKED CANDIDATE ROOT CAUSES:")
    if not report.ranked_candidates:
        lines.append("   (None identified)")
    else:
        for idx, c in enumerate(report.ranked_candidates, start=1):
            lines.append(f"\n   #{idx} {c.title} [Evidence Score: {c.evidence_score:.2f}]")
            lines.append(f"      Description: {c.description}")
            lines.append(f"      Rationale  : {c.rationale}")
            lines.append("      Score Breakdown:")
            for k, v in c.scoring_breakdown.items():
                lines.append(f"         - {k}: {v:+.2f}")
            lines.append("      Supporting Evidence:")
            for e in c.supporting_evidence:
                lines.append(f"         - [{e.record_type.upper()}:{e.record_id}] {e.summary}")
            if c.contradicting_evidence:
                lines.append("      Contradicting Evidence:")
                for ce in c.contradicting_evidence:
                    lines.append(f"         - [{ce.record_type.upper()}:{ce.record_id}] {ce.summary}")
            if c.missing_evidence:
                lines.append("      Missing Telemetry / Information:")
                for m in c.missing_evidence:
                    lines.append(f"         - {m}")
            lines.append(f"      Uncertainty: {c.uncertainty}")

    lines.append("\n" + "-" * 78)
    lines.append(" REMEDIATION PROPOSAL (FOR HUMAN REVIEW ONLY):")
    if not report.proposal:
        lines.append("   No remediation proposal generated (criteria not met or evidence insufficient).")
    else:
        p = report.proposal
        lines.append(f"   Proposal ID     : {p.proposal_id}")
        lines.append(f"   Target Resource : {p.target_resource}")
        lines.append(f"   Operation       : {p.operation}")
        lines.append(f"   Execution Status: {p.status} (Mandatory Read-Only Invariant)")
        lines.append(f"   Rationale       : {p.rationale}")
        lines.append("   Deterministic Policy Checks:")
        for check in p.policy_checks:
            verdict = "PASSED" if check.passed else "FAILED"
            lines.append(f"      [{verdict}] {check.check_name}: {check.details}")
        lines.append(f"   All Checks Passed: {p.all_policy_checks_passed}")
        lines.append("\n   Proposed Manifest Diff (Unified Diff):")
        lines.append("   " + ("-" * 70))
        for dline in p.diff.splitlines():
            lines.append(f"   {dline}")
        lines.append("   " + ("-" * 70))
        lines.append("   Assumptions & Safety Boundaries:")
        for a in p.assumptions_and_limitations:
            lines.append(f"      * {a}")

    lines.append("=" * 78)
    lines.append(f" Safety Notice: {report.safety_notice}")
    lines.append("=" * 78)
    return "\n".join(lines)


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """HiveMind: Safety-first incident investigation and remediation proposal tool."""
    pass


@main.command(name="analyze")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format: text (terminal friendly) or json (machine readable).",
)
def analyze_command(file_path: Path, output_format: str) -> None:
    """Analyze a structured incident YAML file and report ranked candidate root causes."""
    try:
        content = file_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            click.echo(
                f"Error: Incident file must contain a valid YAML mapping, got {type(data).__name__}.",
                err=True,
            )
            sys.exit(1)

        incident = IncidentEvent.model_validate(data)
    except ValidationError as e:
        click.echo("Error: Incident validation failed against schema contract:", err=True)
        for err in e.errors():
            loc = " -> ".join(str(p) for p in err["loc"])
            click.echo(f"  - [{loc}]: {err['msg']}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error reading incident file: {e}", err=True)
        sys.exit(1)

    try:
        engine = DeterministicCorrelationEngine(incident)
        report = engine.analyze()

        if output_format == "json":
            click.echo(report.model_dump_json(indent=2))
        else:
            click.echo(format_report_text(report))

        sys.exit(0)
    except Exception as e:
        click.echo(f"Unexpected internal analysis error: {e}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
