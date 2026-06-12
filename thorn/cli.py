"""Thorn command-line interface.

Commands::

    thorn start --policy ./policy.yaml --upstream https://api.openai.com
    thorn audit verify --db ./thorn.db
    thorn audit report --db ./thorn.db --last 24h
    thorn audit report --db ./thorn.db --session <session_id>
    thorn version
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

import thorn
from thorn.backends import BACKENDS
from thorn.core.audit import AuditLog
from thorn.policy.schema import PolicyError, load_policy

app = typer.Typer(
    name="thorn",
    help="Runtime semantic security layer for LLM applications.",
    no_args_is_help=True,
)
audit_app = typer.Typer(
    help="Inspect and verify the tamper-evident audit log.", no_args_is_help=True
)
app.add_typer(audit_app, name="audit")

console = Console()
err_console = Console(stderr=True)


@app.command()
def start(
    policy: Annotated[Path, typer.Option("--policy", help="Path to the policy YAML file.")],
    upstream: Annotated[str, typer.Option("--upstream", help="Upstream LLM API base URL.")],
    port: Annotated[int, typer.Option("--port", help="Port to listen on.")] = 8080,
    host: Annotated[str, typer.Option("--host", help="Host to bind.")] = "127.0.0.1",
    backend: Annotated[
        str, typer.Option("--backend", help=f"Upstream wire format: {', '.join(BACKENDS)}.")
    ] = "openai",
    db: Annotated[Path, typer.Option("--db", help="SQLite path for sessions + audit log.")] = Path(
        "./thorn.db"
    ),
    ollama_url: Annotated[
        str, typer.Option("--ollama-url", help="Ollama URL for the semantic layer.")
    ] = "http://localhost:11434",
    ollama_model: Annotated[
        str, typer.Option("--ollama-model", help="Ollama model for the semantic layer.")
    ] = "llama3.2",
) -> None:
    """Start the Thorn reverse proxy (Mode 1)."""
    import uvicorn

    from thorn.core.proxy import create_app

    if backend not in BACKENDS:
        err_console.print(
            f"[red]unknown backend {backend!r}[/red] — choose one of: {', '.join(BACKENDS)}"
        )
        raise typer.Exit(1)

    try:
        loaded = load_policy(policy)
    except PolicyError as exc:
        err_console.print(f"[red]policy error:[/red] {exc}")
        raise typer.Exit(1) from None

    backend_instance = BACKENDS[backend](upstream)
    console.print(
        f"[green]thorn[/green] starting: policy=[bold]{loaded.name}[/bold] "
        f"v{loaded.version}, backend={backend}, upstream={upstream}"
    )
    console.print(f"point your client base_url at [bold]http://{host}:{port}[/bold]")

    proxy_app = create_app(
        loaded,
        backend_instance,
        db_path=str(db),
        ollama_url=ollama_url,
        ollama_model=ollama_model,
    )
    uvicorn.run(proxy_app, host=host, port=port, log_level="info")


@audit_app.command()
def verify(
    db: Annotated[Path, typer.Option("--db", help="Audit database path.")] = Path("./thorn.db"),
) -> None:
    """Verify the integrity of the audit hash chain.

    Exits 0 if the chain is intact, 1 if it has been tampered with.
    """
    if not db.exists():
        err_console.print(f"[red]audit database not found:[/red] {db}")
        raise typer.Exit(1)

    log = AuditLog(db)
    result = log.verify()
    log.close()

    if result.intact:
        console.print(
            f"[green]✓ audit chain intact[/green] — {result.entries_checked} entries verified"
        )
        raise typer.Exit(0)
    err_console.print(f"[red]✗ audit chain BROKEN[/red] — {result.detail}")
    raise typer.Exit(1)


@audit_app.command()
def report(
    db: Annotated[Path, typer.Option("--db", help="Audit database path.")] = Path("./thorn.db"),
    last: Annotated[
        str | None, typer.Option("--last", help="Time window, e.g. 24h, 7d, 30m.")
    ] = None,
    session: Annotated[str | None, typer.Option("--session", help="Filter by session id.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max entries to display.")] = 50,
) -> None:
    """Summarize recent audit log activity."""
    if not db.exists():
        err_console.print(f"[red]audit database not found:[/red] {db}")
        raise typer.Exit(1)

    log = AuditLog(db)
    since = None
    if last is not None:
        window = _parse_window(last)
        if window is None:
            err_console.print(
                f"[red]invalid --last value {last!r}[/red] — use forms like 30m, 24h, 7d"
            )
            raise typer.Exit(1)
        since = window

    entries = (
        log.entries_last(since)[:limit]
        if since is not None
        else log.entries(session_id=session, limit=limit)
    )
    if session is not None and since is not None:
        entries = [e for e in entries if e.session_id == session]
    log.close()

    if not entries:
        console.print("no audit entries match the given filters")
        return

    actions = Counter(e.policy_decision.action for e in entries)
    summary = ", ".join(f"{action}: {count}" for action, count in actions.most_common())
    console.print(f"[bold]{len(entries)} entries[/bold] — {summary}\n")

    table = Table(show_lines=False)
    table.add_column("timestamp", style="dim")
    table.add_column("session")
    table.add_column("action")
    table.add_column("triggered by")
    table.add_column("worst verdict")

    for entry in entries:
        action = entry.policy_decision.action
        style = {"block": "red", "terminate": "red bold", "warn": "yellow", "redact": "yellow"}.get(
            action, "green"
        )
        worst = _worst_verdict(entry.verdicts)
        table.add_row(
            entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            entry.session_id[:20],
            f"[{style}]{action}[/{style}]",
            ", ".join(entry.policy_decision.triggered_by) or "—",
            worst,
        )
    console.print(table)


@app.command()
def version() -> None:
    """Print the installed Thorn version."""
    console.print(f"thorn {thorn.__version__}")


def _parse_window(value: str) -> timedelta | None:
    """Parse '30m' / '24h' / '7d' into a timedelta."""
    match = re.fullmatch(r"(\d+)([mhd])", value.strip().lower())
    if not match:
        return None
    amount, unit = int(match.group(1)), match.group(2)
    return {
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
    }[unit]


def _worst_verdict(verdicts: list) -> str:
    order = {"benign": 0, "suspicious": 1, "malicious": 2}
    if not verdicts:
        return "—"
    worst = max(verdicts, key=lambda v: order.get(v.verdict, 0))
    return f"{worst.verdict} ({worst.layer})"


if __name__ == "__main__":
    sys.exit(app())
