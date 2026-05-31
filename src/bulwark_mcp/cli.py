"""Command-line interface for bulwark-mcp."""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import aiosqlite
import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from . import __version__
from .benchmark import BenchResult, run_benchmarks_sync
from .config import Settings, resolve_settings
from .detectors.llm import OllamaClassifier
from .detectors.rules import RulesEngine
from .doctor import CheckResult, doctor_sync
from .inspector import Inspector
from .lint import lint_path
from .models import parse_frame
from .policy import Policy, default_policy
from .proxy import run_proxy
from .stats import Stats, compute_stats, parse_since
from .storage import Storage, stream_events

# All diagnostic output goes to stderr — stdout is reserved for JSON-RPC frames
# while ``run`` is active.
_console = Console(stderr=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, package_name="bulwark-mcp")
def main() -> None:
    """bulwark-mcp — prompt-injection firewall for MCP servers."""


@main.command("run")
@click.option(
    "--server",
    required=True,
    help='Full command for the underlying MCP server, e.g. "npx -y @mcp/server-filesystem /tmp".',
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
@click.option(
    "--detector/--no-detector",
    default=None,
    help="Force the detection layer on or off (overrides config file).",
)
@click.option(
    "--policies",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML policy file (default: built-in policy).",
)
@click.option(
    "--health-port",
    type=int,
    default=0,
    show_default=True,
    help="Bind a loopback health endpoint on 127.0.0.1:<port>/health (0 = disabled).",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase diagnostic verbosity (-v: INFO, -vv: DEBUG).",
)
def cmd_run(
    server: str,
    db_path: Path | None,
    config: Path | None,
    detector: bool | None,
    policies: Path | None,
    health_port: int,
    verbose: int,
) -> None:
    """Run the proxy. The MCP client (e.g. Claude Desktop) invokes this."""
    _setup_logging(verbose)
    settings = resolve_settings(
        cli_db_path=db_path,
        cli_config=config,
        cli_detector_enabled=detector,
        cli_policies=policies,
    )
    _console.log(f"audit log: {settings.db_path}")
    _console.log(f"server   : {server}")
    if settings.detector.enabled:
        _console.log(
            f"detector : ON (rules={settings.detector.rules_dir}, "
            f"llm={'on' if settings.detector.llm_enabled else 'off'})"
        )
    else:
        _console.log("detector : off (audit-only mode)")
    if health_port > 0:
        _console.log(f"health  : http://127.0.0.1:{health_port}/health")
    try:
        result = asyncio.run(run_proxy(server, settings=settings, health_port=health_port))
    except KeyboardInterrupt:
        _console.log("interrupted")
        sys.exit(130)
    except Exception:
        _console.print_exception()
        sys.exit(1)
    if result.events_dropped:
        _console.log(
            f"warning: {result.events_dropped} events were dropped "
            f"due to a full queue — raise queue_max"
        )
    sys.exit(result.exit_code)


@main.command("logs")
@click.option(
    "--tail",
    type=int,
    default=50,
    show_default=True,
    help="Number of recent events to display.",
)
@click.option("--follow", "-f", is_flag=True, help="Stream new events as they arrive.")
@click.option(
    "--verdict",
    type=click.Choice(["PASS", "WARN", "BLOCK"]),
    default=None,
    help="Filter to events with this detection verdict.",
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
def cmd_logs(
    tail: int,
    follow: bool,
    verdict: str | None,
    db_path: Path | None,
    config: Path | None,
) -> None:
    """Inspect the audit log."""
    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    if not settings.db_path.exists():
        _console.print(
            f"[yellow]no audit log at {settings.db_path}. Run "
            f"`bulwark run --server ...` first.[/yellow]"
        )
        sys.exit(1)
    try:
        if follow:
            asyncio.run(_run_follow(settings, initial_tail=tail, verdict=verdict))
        else:
            asyncio.run(_run_tail(settings, tail, verdict=verdict))
    except KeyboardInterrupt:
        sys.exit(130)


async def _run_tail(settings: Settings, tail: int, *, verdict: str | None) -> None:
    async with Storage(settings.db_path) as storage:
        rows = await storage.latest_events(limit=tail, verdict=verdict)
    if not rows:
        _console.print("[dim]no events yet.[/dim]")
        return
    Console().print(_render_table(rows))


async def _run_follow(settings: Settings, *, initial_tail: int, verdict: str | None) -> None:
    out = Console()
    table = _empty_table()
    with Live(table, console=out, refresh_per_second=8, transient=False) as live:
        async with Storage(settings.db_path) as storage:
            async for row in stream_events(storage, initial_tail=initial_tail):
                if verdict is not None and row["det_verdict"] != verdict:
                    continue
                _add_row(table, row)
                live.update(table)


@main.command("detect")
@click.argument("text", required=True)
@click.option(
    "--direction",
    type=click.Choice(["client_to_server", "server_to_client"]),
    default="server_to_client",
    show_default=True,
    help="Direction to scan with (s2c uses both rules and LLM; c2s rules only).",
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Skip the LLM classifier (rules-only fast path).",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
@click.option(
    "--policies",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML policy file (default: built-in policy).",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase diagnostic verbosity (-v: INFO, -vv: DEBUG).",
)
def cmd_detect(
    text: str,
    direction: str,
    no_llm: bool,
    config: Path | None,
    policies: Path | None,
    verbose: int,
) -> None:
    """Run the detection layer over a single string and print the verdict.

    Useful for testing rule packs and policies without spinning up the proxy.
    The LLM call (if not disabled) goes through the configured Ollama
    endpoint exactly as it would in a live session, so this also doubles as a
    quick "is my Ollama set up correctly?" check.
    """
    _setup_logging(verbose)
    settings = resolve_settings(
        cli_config=config,
        cli_detector_enabled=True,
        cli_policies=policies,
    )
    try:
        result = asyncio.run(_run_detect(settings, text=text, direction=direction, no_llm=no_llm))
    except FileNotFoundError as exc:
        _console.print(f"[red]error:[/red] {exc}")
        sys.exit(2)
    if _is_ollama_unreachable(result, no_llm=no_llm, settings=settings):
        _print_ollama_unreachable(settings)
        sys.exit(2)
    _print_detection_result(result)
    sys.exit(0 if result.verdict == "PASS" else 1)


async def _run_detect(settings: Settings, *, text: str, direction: str, no_llm: bool) -> Any:
    rules = RulesEngine.from_directory(settings.detector.rules_dir)
    policy = (
        Policy.from_file(settings.detector.policies_file)
        if settings.detector.policies_file is not None
        else default_policy()
    )

    storage = Storage(settings.db_path)
    await storage.open()
    classifier: OllamaClassifier | None = None
    try:
        if not no_llm and settings.detector.llm_enabled:
            classifier = OllamaClassifier(
                storage=storage,
                url=settings.detector.ollama_url,
                model=settings.detector.ollama_model,
                timeout_ms=settings.detector.timeout_ms,
                cache_ttl_s=settings.detector.cache_ttl_s,
                circuit_threshold=settings.detector.circuit_threshold,
                circuit_open_s=settings.detector.circuit_open_s,
            )
        try:
            inspector = Inspector(
                rules=rules,
                classifier=classifier,
                policy=policy,
                max_latency_ms=settings.detector.max_latency_ms,
                short_circuit_threshold=settings.detector.short_circuit_threshold,
            )
            if direction == "server_to_client":
                wrapped: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "result": {"content": [{"type": "text", "text": text}]},
                }
            else:
                # Wrap as a tools/call request so policy rules that gate on
                # method or rules_hit can fire and the inspector has a
                # JSON-RPC id to bounce back in the synthetic block reply.
                wrapped = {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "tools/call",
                    "params": {"name": "shell", "arguments": {"cmd": text}},
                }
            raw = json.dumps(wrapped, separators=(",", ":"))
            parsed, _ = parse_frame(raw)
            return await inspector.inspect(
                raw=raw,
                parsed=parsed,
                direction=direction,  # type: ignore[arg-type]
                method_hint=getattr(parsed, "method", None),
            )
        finally:
            if classifier is not None:
                await classifier.aclose()
    finally:
        await storage.close()


def _print_detection_result(result: Any) -> None:
    out = Console()
    color = {"PASS": "green", "WARN": "yellow", "BLOCK": "red"}.get(result.verdict, "white")
    out.print(
        f"[bold {color}]{result.verdict}[/bold {color}] "
        f"(score={result.score:.2f}, latency={result.latency_ms} ms)"
    )
    if result.rules_hit:
        out.print("rules hit:")
        for rid in result.rules_hit:
            out.print(f"  • [cyan]{rid}[/cyan]")
    else:
        out.print("rules: [dim]no hit[/dim]")
    classifier_str = (
        f"[bold]{result.classifier}[/bold]" if result.classifier else "[dim]skipped[/dim]"
    )
    out.print(f"classifier: {classifier_str} ([dim]{result.note or 'ok'}[/dim])")
    if result.matched_policy:
        out.print(f"policy: [yellow]{result.matched_policy}[/yellow] → {result.action}")
    else:
        out.print(f"policy: [dim]no match[/dim] → {result.action}")


def _is_ollama_unreachable(result: Any, *, no_llm: bool, settings: Settings) -> bool:
    if no_llm or not settings.detector.llm_enabled:
        return False
    note = getattr(result, "note", None)
    return isinstance(note, str) and note.startswith("error:ConnectError")


def _print_ollama_unreachable(settings: Settings) -> None:
    _console.print(f"Error: Could not reach Ollama at {settings.detector.ollama_url}.")
    _console.print("Suggestions:")
    _console.print("• Start Ollama: ollama serve")
    _console.print(f"• Or pull the model: ollama pull {settings.detector.ollama_model}")
    _console.print('• Or run rules-only: bulwark detect "..." --no-llm')
    _console.print("• Or run bulwark doctor to diagnose your setup.")


def _setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _empty_table() -> Table:
    table = Table(show_lines=False, expand=True)
    table.add_column("id", justify="right", style="dim", no_wrap=True)
    table.add_column("ts", style="dim", no_wrap=True)
    table.add_column("dir", justify="center", no_wrap=True)
    table.add_column("kind", no_wrap=True)
    table.add_column("verdict", justify="center", no_wrap=True)
    table.add_column("method", style="cyan", no_wrap=True)
    table.add_column("msg_id", style="dim", no_wrap=True)
    table.add_column("payload", overflow="ellipsis", no_wrap=True)
    return table


def _render_table(rows: list[aiosqlite.Row]) -> Table:
    table = _empty_table()
    for row in rows:
        _add_row(table, row)
    return table


_DIRECTION_ARROW = {
    "client_to_server": Text("→", style="bold blue"),
    "server_to_client": Text("←", style="bold green"),
}

_KIND_STYLE = {
    "request": "blue",
    "response": "green",
    "notification": "yellow",
    "error": "bold red",
    "raw": "dim",
    "parse_error": "bold red",
}


_VERDICT_STYLE = {
    "PASS": "green",
    "WARN": "yellow",
    "BLOCK": "bold red",
}


def _add_row(table: Table, row: aiosqlite.Row) -> None:
    table.add_row(
        str(row["id"]),
        _short_ts(row["ts"]),
        _DIRECTION_ARROW.get(row["direction"], Text("?")),
        Text(row["kind"], style=_KIND_STYLE.get(row["kind"], "white")),
        _verdict_cell(row),
        row["method"] or "",
        row["msg_id"] or "",
        _payload_summary(row),
    )


def _verdict_cell(row: aiosqlite.Row) -> Text:
    verdict = row["det_verdict"]
    if not verdict:
        return Text("—", style="dim")
    return Text(verdict, style=_VERDICT_STYLE.get(verdict, "white"))


def _short_ts(ts: str) -> str:
    """Trim ISO-8601 to HH:MM:SS.fff for the viewer (the full ts is in the DB)."""
    if "T" not in ts:
        return ts
    after_t = ts.split("T", 1)[1]
    return after_t[:12]


def _payload_summary(row: aiosqlite.Row) -> str:
    for column in ("params_json", "result_json", "error_json"):
        value = row[column]
        if value:
            return _compact(value)
    return _compact(row["raw"])


def _compact(value: str, max_len: int = 120) -> str:
    s = value.strip()
    try:
        decoded: Any = json.loads(s)
        s = json.dumps(decoded, separators=(",", ":"), ensure_ascii=False)
    except json.JSONDecodeError:
        pass
    if len(s) > max_len:
        return s[: max_len - 1] + "…"
    return s


@main.command("stats")
@click.option(
    "--since",
    default="7d",
    show_default=True,
    help="Window: '7d' / '24h' / '1h' / '30m'.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit JSON (pretty-printed) instead of a Rich table.",
)
@click.option(
    "--compact",
    is_flag=True,
    help="With --json, emit a single-line payload (for cron / piping).",
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
def cmd_stats(
    since: str,
    as_json: bool,
    compact: bool,
    db_path: Path | None,
    config: Path | None,
) -> None:
    """Read-only summary of the audit log: counts, top rules, latency."""
    if compact and not as_json:
        _console.print("[red]error:[/red] --compact requires --json")
        sys.exit(2)
    try:
        delta = parse_since(since)
    except ValueError as exc:
        _console.print(f"[red]error:[/red] {exc}")
        sys.exit(2)

    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    if not settings.db_path.exists():
        _console.print(
            f"[yellow]no audit log at {settings.db_path}. Run "
            "`bulwark run --server ...` first.[/yellow]"
        )
        sys.exit(1)
    stats = asyncio.run(_run_stats(settings, since=delta))
    if as_json:
        indent = None if compact else 2
        click.echo(json.dumps(stats.to_dict(), indent=indent, default=str))
    else:
        _print_stats_table(stats)


async def _run_stats(settings: Settings, *, since: timedelta) -> Stats:
    async with Storage(settings.db_path) as storage:
        return await compute_stats(storage, since=since)


def _print_stats_table(stats: Stats) -> None:
    out = Console()
    period = f"{stats.period_start.isoformat()} → {stats.period_end.isoformat()}"
    out.print(f"[bold]Stats[/bold] [dim]({period})[/dim]")

    verdict_table = Table(show_lines=False)
    verdict_table.add_column("verdict", style="bold")
    verdict_table.add_column("count", justify="right")
    for v in ("PASS", "WARN", "BLOCK"):
        style = {"PASS": "green", "WARN": "yellow", "BLOCK": "bold red"}[v]
        verdict_table.add_row(
            Text(v, style=style),
            Text(str(stats.verdicts.get(v, 0)), style=style),
        )
    verdict_table.add_row("[dim]TOTAL[/dim]", str(stats.total_events))
    out.print(verdict_table)

    if stats.top_rules:
        out.print("\n[bold]Top rules:[/bold]")
        for i, hit in enumerate(stats.top_rules, 1):
            out.print(f"  {i}. [cyan]{hit.id}[/cyan] ({hit.count})")
    else:
        out.print("\n[dim]no rule hits in this window[/dim]")

    if stats.latency_p50_ms is not None and stats.latency_p95_ms is not None:
        out.print(
            f"\n[bold]Inspector latency:[/bold] "
            f"p50={stats.latency_p50_ms:.1f} ms, "
            f"p95={stats.latency_p95_ms:.1f} ms"
        )


@main.command("benchmark")
@click.option(
    "--iterations",
    "-n",
    type=int,
    default=200,
    show_default=True,
    help="Iterations per workload after the warm-up.",
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
def cmd_benchmark(iterations: int, db_path: Path | None, config: Path | None) -> None:
    """Measure local detection latency.

    Three workloads (rules detector, inspector cache hit, end-to-end
    cat-server round-trip). Prints p50/p95/p99 per workload.
    Useful when filing a bug or when deciding if the detector is fast
    enough for your traffic.
    """
    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    _console.log(f"running {iterations} iterations per workload (after warm-up)…")
    results = run_benchmarks_sync(settings, iters=iterations)
    _print_benchmark_table(results)


def _print_benchmark_table(results: list[BenchResult]) -> None:
    out = Console()
    table = Table(show_lines=False, expand=True)
    table.add_column("workload", no_wrap=True)
    table.add_column("iters", justify="right")
    table.add_column("p50 (ms)", justify="right")
    table.add_column("p95 (ms)", justify="right")
    table.add_column("p99 (ms)", justify="right")
    for r in results:
        table.add_row(
            r.name,
            str(r.iterations),
            f"{r.p50_ms:.2f}",
            f"{r.p95_ms:.2f}",
            f"{r.p99_ms:.2f}",
        )
    out.print(table)
    for r in results:
        if r.note:
            out.print(f"[yellow]note ({r.name}):[/yellow] {r.note}")


@main.command("doctor")
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
def cmd_doctor(db_path: Path | None, config: Path | None) -> None:
    """Diagnose the local environment.

    Runs four checks (Python version, Ollama, audit DB, rules + policy)
    and prints a Rich table. Exit code reflects worst status:
    0 = all pass, 1 = at least one warn, 2 = at least one fail.
    """
    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    results, overall = doctor_sync(settings)
    _print_doctor_table(results, overall)
    sys.exit({"pass": 0, "warn": 1, "fail": 2}[overall])


@main.command("version")
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
def cmd_version(db_path: Path | None, config: Path | None) -> None:
    """Print extended version and environment information."""
    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    Console().print(_render_version_info(settings))


def _render_version_info(settings: Settings) -> str:
    rules = RulesEngine.from_directory(settings.detector.rules_dir)
    packs = sorted(settings.detector.rules_dir.glob("*.yaml"))
    schema = asyncio.run(_read_schema_version(settings))
    detector = "on" if settings.detector.enabled else "off (config default)"
    install_path = Path(__file__).resolve().parent
    implementation = getattr(sys.implementation, "name", "Python")

    return "\n".join(
        (
            f"bulwark-mcp {__version__}",
            f"Python {platform.python_version()} ({implementation}, {sys.platform})",
            f"Platform: {platform.platform()}",
            f"Rules loaded: {len(rules)} from {len(packs)} packs",
            f"Detector: {detector}",
            f"DB schema: v{schema}",
            f"Install path: {install_path}",
        )
    )


async def _read_schema_version(settings: Settings) -> int:
    async with Storage(settings.db_path) as storage:
        return await storage._current_schema_version()


def _print_doctor_table(results: list[CheckResult], overall: str) -> None:
    out = Console()
    table = Table(show_lines=False, expand=True)
    table.add_column("check", no_wrap=True)
    table.add_column("status", justify="center", no_wrap=True)
    table.add_column("detail")
    style = {"pass": "green", "warn": "yellow", "fail": "bold red"}
    for r in results:
        table.add_row(
            r.name,
            Text(r.status.upper(), style=style[r.status]),
            r.detail,
        )
    out.print(table)
    for r in results:
        if r.suggestion and r.status != "pass":
            out.print(f"  [bold]→[/bold] [dim]{r.name}:[/dim] {r.suggestion}")
    out.print()
    out.print(f"overall: [{style[overall]}]{overall.upper()}[/{style[overall]}]")


@main.group("rules")
def cmd_rules() -> None:
    """Tools for authoring and validating rule packs."""


@cmd_rules.command("lint")
@click.argument(
    "target",
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--strict",
    is_flag=True,
    help="Apply built-in-pack quality gates (severity_tier, attack_examples, source URL).",
)
def cmd_rules_lint(target: Path, strict: bool) -> None:
    """Validate a YAML rule pack (file or directory).

    Exit 0 = passes (basic mode tolerates missing recommendations).
    Exit 1 = errors (any mode) or warnings (strict mode only).
    """
    issues = lint_path(target, strict=strict)
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]

    out = Console()
    for issue in issues:
        style = "red" if issue.severity == "error" else "yellow"
        out.print(f"[{style}]{issue.render()}[/{style}]")

    summary_lines = []
    if errors:
        summary_lines.append(f"[bold red]{len(errors)} error(s)[/bold red]")
    if warnings:
        summary_lines.append(f"[bold yellow]{len(warnings)} warning(s)[/bold yellow]")
    if not summary_lines:
        out.print("[bold green]ok[/bold green]")
    else:
        out.print(" • ".join(summary_lines))

    fail = bool(errors) or (strict and bool(warnings))
    sys.exit(1 if fail else 0)


if __name__ == "__main__":  # pragma: no cover
    main()
