"""HiveMind Command Line Interface.

Provides human-reviewable terminal reports for incident telemetry and remediation proposals.
Strictly read-only: Never applies mutations to production.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import ValidationError

from hivemind import __version__
from hivemind.engine import DeterministicCorrelationEngine
from hivemind.logging_config import setup_logging
from hivemind.models import AnalysisStatus, IncidentAnalysisReport, IncidentEvent
from hivemind.redaction import redact_secrets


def should_use_color(no_color: bool = False) -> bool:
    """Determine whether ANSI colors should be used based on flag and environment."""
    if no_color or bool(os.environ.get("NO_COLOR")):
        return False
    return True


def colorize(text: str, color: bool = True, **kwargs: Any) -> str:
    """Apply click.style if color is enabled, otherwise return plain text."""
    if not color:
        return text
    return click.style(text, **kwargs)


def format_report_text(report: IncidentAnalysisReport, no_color: bool = False) -> str:
    """Formats incident report into clear, human-readable terminal output."""
    use_color = should_use_color(no_color)
    lines: list[str] = []
    lines.append(colorize("=" * 78, color=use_color, fg="white", bold=True))
    lines.append(colorize(" HIVEMIND INCIDENT INVESTIGATION REPORT (READ-ONLY MVP)", color=use_color, fg="white", bold=True))
    lines.append(" Notice: No production changes were applied. Analysis is read-only.")
    lines.append(colorize("=" * 78, color=use_color, fg="white", bold=True))
    lines.append(f" Incident ID  : {report.incident_id}")
    lines.append(f" Environment  : {report.environment}")
    lines.append(f" Time Window  : {report.analysis_window_start.isoformat()} to {report.analysis_window_end.isoformat()}")

    status_color = "green" if report.status == AnalysisStatus.DIAGNOSED else "yellow"
    status_tag = f"[{colorize(report.status.value, color=use_color, fg=status_color)}]"
    lines.append(f" Status       : {status_tag}")
    lines.append(f" Summary      : {report.summary}")
    lines.append(colorize("-" * 78, color=use_color, fg="white", bold=True))

    if report.status == AnalysisStatus.INCONCLUSIVE and report.inconclusive_reasons:
        lines.append(colorize(" INCONCLUSIVE AUDIT NOTES:", color=use_color, fg="yellow", bold=True))
        for reason in report.inconclusive_reasons:
            lines.append(f"   * {colorize(reason, color=use_color, fg='yellow')}")
        lines.append(colorize("-" * 78, color=use_color, fg="white", bold=True))
    elif report.status == AnalysisStatus.DIAGNOSED and report.telemetry_warnings:
        lines.append(colorize(" TELEMETRY WARNINGS & LIMITATIONS:", color=use_color, fg="yellow", bold=True))
        for warning in report.telemetry_warnings:
            lines.append(f"   * {warning}")
        lines.append(colorize("-" * 78, color=use_color, fg="white", bold=True))

    lines.append(colorize(" RANKED CANDIDATE ROOT CAUSES:", color=use_color, fg="white", bold=True))
    if not report.ranked_candidates:
        lines.append("   (None identified)")
    else:
        for idx, c in enumerate(report.ranked_candidates, start=1):
            score_str = colorize(f"{c.evidence_score:.2f}", color=use_color, fg="cyan")
            lines.append(f"\n   #{idx} {c.title} [Evidence Score: {score_str}]")
            lines.append(f"      Description: {c.description}")
            lines.append(f"      Rationale  : {c.rationale}")
            lines.append("      Score Breakdown:")
            for k, v in c.scoring_breakdown.items():
                v_str = colorize(f"{v:+.2f}", color=use_color, fg="cyan")
                lines.append(f"         - {k}: {v_str}")
            lines.append("      Supporting Evidence:")
            for e in c.supporting_evidence:
                lines.append(f"         - [{e.record_type.upper()}:{e.record_id}] {e.summary}")
            if c.contradicting_evidence:
                lines.append(colorize("      Contradicting Evidence:", color=use_color, fg="red"))
                for ce in c.contradicting_evidence:
                    lines.append(colorize(f"         - [{ce.record_type.upper()}:{ce.record_id}] {ce.summary}", color=use_color, fg="red"))
            if c.missing_evidence:
                lines.append("      Missing Telemetry / Information:")
                for m in c.missing_evidence:
                    lines.append(f"         - {m}")
            lines.append(f"      Uncertainty: {c.uncertainty}")

    lines.append("\n" + colorize("-" * 78, color=use_color, fg="white", bold=True))
    lines.append(colorize(" REMEDIATION PROPOSAL (FOR HUMAN REVIEW ONLY):", color=use_color, fg="white", bold=True))
    generation = report.proposal_generation
    lines.append(f"   Generation      : {generation.status.value} ({generation.reason_code.value})")
    lines.append(f"   Generation Note : {generation.message}")
    if generation.failed_policy_checks:
        lines.append(colorize(f"   Rejected Checks : {', '.join(generation.failed_policy_checks)}", color=use_color, fg="red"))
    if not report.proposal:
        lines.append("   No remediation proposal generated.")
    else:
        p = report.proposal
        lines.append(f"   Proposal ID     : {p.proposal_id}")
        lines.append(f"   Target Resource : {p.target_resource}")
        lines.append(f"   Operation       : {p.operation}")
        lines.append(f"   Execution Status: {p.status} (Mandatory Read-Only Invariant)")
        lines.append(f"   Rationale       : {p.rationale}")
        lines.append(
            f"   Telemetry Evidence: {generation.telemetry_evidence_count} cited signal/log record(s)"
        )
        lines.append("   Proposal Evidence References:")
        for evidence in p.evidence_references:
            lines.append(
                f"      - [{evidence.record_type.upper()}:{evidence.record_id}] {evidence.summary}"
            )
        lines.append("   Deterministic Policy Checks:")
        for check in p.policy_checks:
            verdict_color = "green" if check.passed else "red"
            verdict = colorize("PASSED" if check.passed else "FAILED", color=use_color, fg=verdict_color)
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

    lines.append(colorize("=" * 78, color=use_color, fg="white", bold=True))
    lines.append(f" Safety Notice: {report.safety_notice}")
    lines.append(colorize("=" * 78, color=use_color, fg="white", bold=True))
    return "\n".join(lines)


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--log-format",
    type=click.Choice(["plain", "json"], case_sensitive=False),
    default="plain",
    help="Logging format: plain text or structured JSON.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored terminal output.",
)
def main(log_format: str = "plain", no_color: bool = False) -> None:
    """HiveMind: Safety-first incident investigation and remediation proposal tool."""
    level = logging.INFO if log_format == "json" else logging.WARNING
    setup_logging(log_format=log_format, level=level)


@main.command(name="analyze")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format: text (terminal friendly) or json (machine readable).",
)
@click.option(
    "--log-format",
    type=click.Choice(["plain", "json"], case_sensitive=False),
    default=None,
    help="Logging format: plain text or structured JSON.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Directory to write the JSON report to instead of stdout.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored terminal output.",
)
def analyze_command(
    file_path: Path,
    output_format: str,
    log_format: str | None = None,
    output_dir: Path | None = None,
    no_color: bool = False,
) -> None:
    """Analyze a structured incident YAML file and report ranked candidate root causes."""
    if log_format is not None:
        level = logging.INFO if log_format == "json" else logging.WARNING
        setup_logging(log_format=log_format, level=level)

    use_color = should_use_color(no_color)
    try:
        content = file_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            err_msg = colorize(
                f"Error: Incident file must contain a valid YAML mapping, got {type(data).__name__}.",
                color=use_color,
                fg="red",
            )
            click.echo(err_msg, err=True)
            sys.exit(1)

        incident = IncidentEvent.model_validate(data)
    except ValidationError as e:
        click.echo(colorize("Error: Incident validation failed against schema contract:", color=use_color, fg="red"), err=True)
        for err in e.errors():
            loc = " -> ".join(str(p) for p in err["loc"])
            click.echo(colorize(f"  - [{loc}]: {redact_secrets(err['msg'])}", color=use_color, fg="red"), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(colorize(f"Error reading incident file: {redact_secrets(str(e))}", color=use_color, fg="red"), err=True)
        sys.exit(1)

    try:
        engine = DeterministicCorrelationEngine(incident)
        report = engine.analyze()

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            json_report = report.model_dump_json(indent=2)
            out_file = output_dir / f"{report.incident_id}.json"
            out_file.write_text(json_report, encoding="utf-8")
            alias_file = output_dir / f"{file_path.stem}.json"
            if alias_file != out_file:
                alias_file.write_text(json_report, encoding="utf-8")
            click.echo(f"Report written to {out_file}")
            sys.exit(0)

        if output_format == "json":
            click.echo(report.model_dump_json(indent=2))
        else:
            click.echo(format_report_text(report, no_color=no_color))

        sys.exit(0)
    except Exception as e:
        click.echo(colorize(f"Unexpected internal analysis error: {redact_secrets(str(e))}", color=use_color, fg="red"), err=True)
        sys.exit(2)


@main.command(name="batch")
@click.argument("directory_path", type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored terminal output.",
)
@click.option(
    "--log-format",
    type=click.Choice(["plain", "json"], case_sensitive=False),
    default=None,
    help="Logging format: plain text or structured JSON.",
)
def batch_command(
    directory_path: Path,
    no_color: bool = False,
    log_format: str | None = None,
) -> None:
    """Process all *.yaml files in a directory and output a summary table."""
    if log_format is not None:
        level = logging.INFO if log_format == "json" else logging.WARNING
        setup_logging(log_format=log_format, level=level)

    use_color = should_use_color(no_color)
    yaml_files = sorted(list(directory_path.glob("*.yaml")) + list(directory_path.glob("*.yml")))
    if not yaml_files:
        click.echo(colorize(f"No YAML files found in {directory_path}", color=use_color, fg="yellow"))
        sys.exit(0)

    rows: list[dict[str, str]] = []
    has_validation_failure = False
    has_internal_error = False

    for file_path in yaml_files:
        try:
            content = file_path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                has_validation_failure = True
                rows.append({
                    "file": file_path.name,
                    "status": "INVALID",
                    "candidate": "-",
                    "score": "-",
                    "proposal": "-",
                })
                continue
            incident = IncidentEvent.model_validate(data)
        except ValidationError:
            has_validation_failure = True
            rows.append({
                "file": file_path.name,
                "status": "VALIDATION_FAILED",
                "candidate": "-",
                "score": "-",
                "proposal": "-",
            })
            continue
        except Exception:
            has_validation_failure = True
            rows.append({
                "file": file_path.name,
                "status": "PARSE_ERROR",
                "candidate": "-",
                "score": "-",
                "proposal": "-",
            })
            continue

        try:
            engine = DeterministicCorrelationEngine(incident)
            report = engine.analyze()
            top_cand = report.ranked_candidates[0].title if report.ranked_candidates else "-"
            score_val = f"{report.ranked_candidates[0].evidence_score:.2f}" if report.ranked_candidates else "-"
            proposal_val = (
                report.proposal.proposal_id
                if report.proposal
                else report.proposal_generation.status.value
            )
            rows.append({
                "file": file_path.name,
                "status": report.status.value,
                "candidate": top_cand,
                "score": score_val,
                "proposal": proposal_val,
            })
        except Exception:
            has_internal_error = True
            rows.append({
                "file": file_path.name,
                "status": "INTERNAL_ERROR",
                "candidate": "-",
                "score": "-",
                "proposal": "-",
            })

    header = "| File | Status | Top Candidate | Score | Proposal |"
    divider = "| --- | --- | --- | --- | --- |"
    click.echo(colorize(header, color=use_color, fg="white", bold=True))
    click.echo(divider)
    for r in rows:
        st = r["status"]
        if st == "DIAGNOSED":
            st_styled = colorize(st, color=use_color, fg="green")
        elif st == "INCONCLUSIVE":
            st_styled = colorize(st, color=use_color, fg="yellow")
        else:
            st_styled = colorize(st, color=use_color, fg="red")

        sc = r["score"]
        sc_styled = colorize(sc, color=use_color, fg="cyan") if sc != "-" else "-"
        click.echo(f"| {r['file']} | {st_styled} | {r['candidate']} | {sc_styled} | {r['proposal']} |")

    if has_internal_error:
        sys.exit(2)
    elif has_validation_failure:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
