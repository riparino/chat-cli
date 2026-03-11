#!/usr/bin/env python3
"""
JSM AI Triage Tool – CLI entry point.

Modes:
  auth    – OAuth 2.0 login for Atlassian / Azure / GitHub
  triage  – triage one or more tickets (interactive or batch)
  watch   – continuously watch a queue and triage new tickets
  chat    – free-form chat with the AI (optionally anchored to a ticket)
  status  – show configured providers and JSM connection info

Usage examples:
  python -m jsm_triage auth atlassian
  python -m jsm_triage auth github
  python -m jsm_triage auth azure
  python -m jsm_triage auth status
  python -m jsm_triage triage IT-42
  python -m jsm_triage triage --queue 1 --service-desk 2 --limit 20
  python -m jsm_triage triage --jql "project=IT AND status=Open AND labels!=ai-triaged"
  python -m jsm_triage watch  --queue 1 --service-desk 2 --interval 60
  python -m jsm_triage chat
  python -m jsm_triage chat --ticket IT-42
  python -m jsm_triage status
"""

import argparse
import json
import os
import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load .env from the project root or a jsm_triage/.env
_here = Path(__file__).parent
load_dotenv(_here / ".env")
load_dotenv(_here.parent / ".env")

# Rich imports
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from .triage_engine import TriageEngine, build_provider_chain
from .jsm.client import JSMClient
from .jsm.models import Ticket
from .providers.base import TriageResult
from .auth import AtlassianOAuth, AzureOAuth, GitHubOAuth, PROVIDER_LABELS
from .auth.token_store import TokenStore

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

console = Console()

# Shared token store for the whole process
_token_store = TokenStore()

# Priority display config
_PRIORITY_STYLE = {
    "Critical": ("bold white on dark_red",   "● Critical"),
    "High":     ("bold red",                  "● High"),
    "Medium":   ("bold yellow",               "● Medium"),
    "Low":      ("bold green",                "● Low"),
}

_ALL_PROVIDER_NAMES = [
    "Azure OpenAI",
    "GitHub Copilot",
    "OpenAI (ChatGPT)",
    "Microsoft Copilot",
    "Atlassian Rovo",
]


# ---------------------------------------------------------------------------
# One-off spinner context manager (used by several commands below)
# ---------------------------------------------------------------------------

@contextmanager
def _spinner(description: str):
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        transient=True,
        console=console,
    ) as prog:
        t = prog.add_task(description, total=None)
        yield
        prog.update(t, completed=True)


# ---------------------------------------------------------------------------
# Rich helpers
# ---------------------------------------------------------------------------

def _banner():
    console.print(
        Panel(
            "[bold cyan]JSM AI Triage Tool[/bold cyan]  ·  "
            "[dim]Atlassian JSM + Multi-Provider AI[/dim]",
            box=box.DOUBLE_EDGE,
            padding=(0, 4),
            style="bold",
        )
    )


def _priority_text(priority: str) -> Text:
    style, label = _PRIORITY_STYLE.get(priority, ("bold white", f"● {priority}"))
    return Text(label, style=style)


def _render_result(ticket: Ticket, result: TriageResult, verbose: bool = False):
    """Render a triage result as a rich Panel."""
    p_style, _ = _PRIORITY_STYLE.get(result.priority, ("bold white", ""))
    border_color = {
        "Critical": "dark_red",
        "High":     "red",
        "Medium":   "yellow",
        "Low":      "green",
    }.get(result.priority, "cyan")

    # Build the content table
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", min_width=14)
    grid.add_column()

    grid.add_row("Provider", f"{result.provider_used}  [dim]({result.confidence:.0%} confidence)[/dim]")
    grid.add_row("Priority", _priority_text(result.priority))
    grid.add_row("Category", f"{result.category}[dim] / {result.subcategory}[/dim]")
    if result.suggested_team:
        grid.add_row("Team", result.suggested_team)
    if result.suggested_assignee:
        grid.add_row("Assignee", result.suggested_assignee)
    if result.estimated_resolution:
        grid.add_row("Est. SLA", result.estimated_resolution)

    grid.add_row("", "")
    grid.add_row("Summary", Text(result.summary, overflow="fold"))

    if result.suggested_actions:
        actions_text = Text()
        for i, action in enumerate(result.suggested_actions, 1):
            actions_text.append(f"  {i}. {action}\n")
        grid.add_row("Actions", actions_text)

    if result.escalate:
        grid.add_row(
            "",
            Text(
                f"⚡ ESCALATE: {result.escalation_reason}",
                style="bold white on dark_red",
            ),
        )

    title = f"[bold]{ticket.key}[/bold]  [dim]·[/dim]  {ticket.summary[:60]}"
    console.print(
        Panel(grid, title=title, border_style=border_color, padding=(1, 2))
    )

    if verbose and result.raw_response:
        console.print(
            Panel(
                result.raw_response,
                title="[dim]Raw JSON[/dim]",
                border_style="dim",
                padding=(0, 1),
            )
        )


def _oauth_status_table() -> Table:
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(min_width=12)
    table.add_column()
    for key, label in PROVIDER_LABELS:
        entry = _token_store.get(key)
        if entry:
            if _token_store.is_expired(key):
                has_refresh = bool(_token_store.refresh_token(key))
                state = Text(
                    "expired (refresh available)" if has_refresh else "expired",
                    style="yellow",
                )
            else:
                state = Text("✓ logged in", style="green")
        else:
            state = Text("not logged in", style="dim")
        table.add_row(label, state)
    return table


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_auth(args, *_):
    target = getattr(args, "target", "status")

    def do_atlassian():
        oauth = AtlassianOAuth(_token_store)
        if not oauth.is_configured():
            console.print("[red]✗[/red] Set [bold]ATLASSIAN_CLIENT_ID[/bold] and "
                          "[bold]ATLASSIAN_CLIENT_SECRET[/bold] in .env first.")
            console.print("  [dim]https://developer.atlassian.com/console/myapps/[/dim]")
            sys.exit(1)
        oauth.login()

    def do_azure():
        oauth = AzureOAuth(_token_store)
        if not oauth.is_configured():
            console.print("[red]✗[/red] Set [bold]AZURE_CLIENT_ID[/bold] and "
                          "[bold]AZURE_TENANT_ID[/bold] in .env first.")
            sys.exit(1)
        oauth.login()

    def do_github():
        oauth = GitHubOAuth(_token_store)
        if not oauth.is_configured():
            console.print("[red]✗[/red] Set [bold]GITHUB_CLIENT_ID[/bold] in .env first.")
            console.print("  [dim]https://github.com/settings/developers[/dim]")
            sys.exit(1)
        oauth.login()

    def do_logout():
        provider = getattr(args, "logout_provider", None)
        if provider:
            _token_store.clear(provider)
            console.print(f"[green]✓[/green] Logged out: {provider}")
        else:
            _token_store.clear_all()
            console.print("[green]✓[/green] Logged out all providers")

    def do_status():
        console.print(Panel(_oauth_status_table(), title="OAuth Sessions", padding=(0, 1)))

    _banner()
    handlers = {
        "atlassian": do_atlassian,
        "azure":     do_azure,
        "github":    do_github,
        "logout":    do_logout,
        "status":    do_status,
    }
    handlers.get(target, do_status)()


def cmd_status(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    _banner()

    # AI providers table
    active_names = {p.name for p in engine.providers}
    ai_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    ai_table.add_column(min_width=3)
    ai_table.add_column()
    for name in _ALL_PROVIDER_NAMES:
        if name in active_names:
            ai_table.add_row("[green]✓[/green]", name)
        else:
            ai_table.add_row("[dim]·[/dim]", Text(name, style="dim"))
    console.print(Panel(ai_table, title="AI Providers", padding=(0, 1)))

    # OAuth table
    console.print(Panel(_oauth_status_table(), title="OAuth Sessions", padding=(0, 1)))

    # JSM connection
    jsm_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    jsm_table.add_column(min_width=14)
    jsm_table.add_column()
    if jsm:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      transient=True, console=console) as prog:
            t = prog.add_task("Connecting to JSM…", total=None)
            try:
                url = jsm.test_connection()
                desks = jsm.list_service_desks()
                prog.update(t, completed=True)
            except Exception as exc:
                prog.update(t, completed=True)
                jsm_table.add_row("[red]✗ Error[/red]", str(exc))
                console.print(Panel(jsm_table, title="JSM Connection", padding=(0, 1)))
                return
        jsm_table.add_row("[green]✓ Connected[/green]", url)
        for d in desks:
            jsm_table.add_row(
                f"  [dim]SD {d.id}[/dim]",
                f"{d.name} [dim]({d.project_key})[/dim]",
            )
    else:
        jsm_table.add_row("[dim]·[/dim]", Text("Not configured", style="dim"))
    console.print(Panel(jsm_table, title="JSM Connection", padding=(0, 1)))


def cmd_triage(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    _banner()

    tickets: list[Ticket] = []

    def _require_jsm(reason: str):
        if not jsm:
            console.print(f"[red]✗[/red] JSM credentials required to {reason}.")
            sys.exit(1)

    if args.ticket_keys:
        _require_jsm("fetch tickets")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      transient=True, console=console) as prog:
            for key in args.ticket_keys:
                t = prog.add_task(f"Fetching [bold]{key}[/bold]…", total=None)
                try:
                    tickets.append(jsm.get_ticket(key))
                    prog.update(t, completed=True)
                except Exception as exc:
                    prog.update(t, completed=True)
                    console.print(f"[red]✗[/red] Could not fetch {key}: {exc}")

    elif args.jql:
        _require_jsm("run JQL search")
        console.print(f"[dim]JQL:[/dim] {args.jql}")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      transient=True, console=console) as prog:
            t = prog.add_task("Searching…", total=None)
            tickets = jsm.search_tickets(args.jql, limit=args.limit)
            prog.update(t, completed=True)

    elif args.service_desk and args.queue:
        _require_jsm("read queue")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      transient=True, console=console) as prog:
            t = prog.add_task(
                f"Fetching queue [bold]{args.queue}[/bold] "
                f"from SD [bold]{args.service_desk}[/bold]…",
                total=None,
            )
            tickets = jsm.get_queue_tickets(args.service_desk, args.queue, limit=args.limit)
            prog.update(t, completed=True)

    else:
        # Interactive single-ticket mode
        try:
            key = console.input("[cyan]Ticket key[/cyan] (e.g. IT-42): ").strip()
            if not key:
                return
            if jsm:
                with _spinner(f"Fetching [bold]{key}[/bold]…"):
                    tickets.append(jsm.get_ticket(key))
            else:
                summary = console.input("[cyan]Summary[/cyan]: ").strip()
                description = console.input("[cyan]Description[/cyan]: ").strip()
                tickets.append(Ticket(
                    key=key, summary=summary, description=description,
                    status="Open", priority="Medium", issue_type="Service Request",
                    reporter="unknown", assignee=None,
                ))
        except (EOFError, KeyboardInterrupt):
            return

    if not tickets:
        console.print("[yellow]No tickets found.[/yellow]")
        return

    console.print(f"\n[bold]Triaging {len(tickets)} ticket(s)…[/bold]\n")
    results: list[tuple[Ticket, TriageResult]] = []

    for ticket in tickets:
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            transient=True,
            console=console,
        ) as prog:
            t = prog.add_task(f"Analysing [bold]{ticket.key}[/bold]…", total=None)
            try:
                if jsm:
                    result = engine.triage_and_apply(
                        ticket, jsm,
                        post_comment=not args.no_comment,
                        update_priority=args.update_priority,
                        add_triage_label=not args.no_label,
                    )
                else:
                    result = engine.triage_ticket(ticket)
                prog.update(t, completed=True)
            except Exception as exc:
                prog.update(t, completed=True)
                console.print(f"[red]✗[/red] {ticket.key} failed: {exc}")
                continue

        results.append((ticket, result))
        _render_result(ticket, result, verbose=args.verbose)

    if args.output_json:
        output = [{"ticket": t.key, "triage": r.to_dict()} for t, r in results]
        Path(args.output_json).write_text(json.dumps(output, indent=2))
        console.print(f"\n[green]✓[/green] Results written to [bold]{args.output_json}[/bold]")

    console.print(Rule())
    console.print(
        f"[bold green]Done[/bold green]  –  "
        f"triaged [bold]{len(results)}[/bold] / {len(tickets)} tickets"
        + (" [dim](dry run – no JSM writes)[/dim]" if engine.dry_run else "")
    )


def cmd_watch(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    if not jsm:
        console.print("[red]✗[/red] JSM credentials required for watch mode.")
        sys.exit(1)

    _banner()
    console.print(
        f"Watching queue [bold]{args.queue}[/bold] on SD [bold]{args.service_desk}[/bold]  "
        f"[dim]· polling every {args.interval}s · Ctrl-C to stop[/dim]\n"
    )

    seen: set[str] = set()
    SEEN_CAP = 10_000
    stop = [False]

    def _sigint(sig, frame):
        console.print("\n[yellow]Stopping watcher…[/yellow]")
        stop[0] = True

    signal.signal(signal.SIGINT, _sigint)

    while not stop[0]:
        try:
            tickets = jsm.get_queue_tickets(args.service_desk, args.queue, limit=args.limit)
            new_tickets = [t for t in tickets if t.key not in seen]

            if new_tickets:
                console.print(
                    f"[dim]{time.strftime('%H:%M:%S')}[/dim]  "
                    f"[bold cyan]{len(new_tickets)} new ticket(s)[/bold cyan]"
                )
                for ticket in new_tickets:
                    seen.add(ticket.key)
                    if len(seen) > SEEN_CAP:
                        to_drop = list(seen)[:SEEN_CAP // 4]
                        seen.difference_update(to_drop)

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("{task.description}"),
                        transient=True,
                        console=console,
                    ) as prog:
                        t = prog.add_task(f"  Triaging [bold]{ticket.key}[/bold]…", total=None)
                        try:
                            result = engine.triage_and_apply(
                                ticket, jsm,
                                post_comment=not args.no_comment,
                                update_priority=args.update_priority,
                                add_triage_label=not args.no_label,
                            )
                            prog.update(t, completed=True)
                        except Exception as exc:
                            prog.update(t, completed=True)
                            console.print(f"  [red]✗[/red] {ticket.key}: {exc}")
                            continue

                    p_style, p_label = _PRIORITY_STYLE.get(
                        result.priority, ("bold white", f"● {result.priority}")
                    )
                    console.print(
                        f"  [bold]{ticket.key}[/bold]  "
                        f"[{p_style}]{p_label}[/{p_style}]  "
                        f"[dim]{result.category}[/dim]"
                    )
            else:
                # Overwrite same line while idle
                console.print(
                    f"[dim]{time.strftime('%H:%M:%S')}  no new tickets[/dim]",
                    end="\r",
                )

        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow] Error polling queue: {exc}")

        time.sleep(args.interval)


def cmd_chat(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.styles import Style as PTStyle
    except ImportError:
        console.print(
            "[yellow]⚠[/yellow] prompt_toolkit not installed – falling back to plain input.\n"
            "  Run: [bold]pip install prompt_toolkit[/bold]"
        )
        _chat_plain(args, engine, jsm)
        return

    _banner()

    ticket: Optional[Ticket] = None
    if args.ticket and jsm:
        with _spinner(f"Fetching context ticket [bold]{args.ticket}[/bold]…"):
            try:
                ticket = jsm.get_ticket(args.ticket)
            except Exception as exc:
                console.print(f"[yellow]⚠[/yellow] Could not fetch ticket context: {exc}")
        if ticket:
            console.print(
                Panel(
                    f"[bold]{ticket.key}[/bold]  {ticket.summary}\n"
                    f"[dim]Status:[/dim] {ticket.status}  "
                    f"[dim]Priority:[/dim] {ticket.priority}",
                    title="Ticket Context",
                    border_style="cyan",
                    padding=(0, 2),
                )
            )

    provider_names = "  ·  ".join(p.name for p in engine.providers)
    console.print(f"[dim]Provider(s):[/dim]  {provider_names}")
    console.print(
        "[dim]Commands:[/dim]  "
        "[bold]/new[/bold] clear history  "
        "[bold]/ticket KEY[/bold] switch context  "
        "[bold]/quit[/bold] exit\n"
    )

    # Slash-command completer
    slash_completer = WordCompleter(
        ["/new", "/quit", "/exit", "/ticket", "/help"],
        sentence=True,
    )

    pt_style = PTStyle.from_dict({
        "prompt":   "ansicyan bold",
        "": "ansiwhite",
    })

    history_file = Path.home() / ".jsm_triage" / "chat_history"
    history_file.parent.mkdir(parents=True, exist_ok=True)

    session: PromptSession = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=slash_completer,
        style=pt_style,
        reserve_space_for_menu=4,
    )

    history: list[dict] = []
    MAX_HISTORY = 40

    while True:
        try:
            user_input = session.prompt("You › ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if not user_input:
            continue

        # Slash commands
        if user_input.lower() in ("/quit", "/exit", "quit", "exit"):
            console.print("[dim]Goodbye.[/dim]")
            break
        if user_input.lower() == "/new":
            history.clear()
            console.print("[green]✓[/green] Conversation cleared.\n")
            continue
        if user_input.lower().startswith("/ticket "):
            new_key = user_input.split(None, 1)[1].strip()
            if jsm:
                with _spinner(f"Fetching [bold]{new_key}[/bold]…"):
                    try:
                        ticket = jsm.get_ticket(new_key)
                        console.print(
                            f"[green]✓[/green] Context → [bold]{ticket.key}[/bold]  {ticket.summary}\n"
                        )
                    except Exception as exc:
                        console.print(f"[red]✗[/red] {exc}\n")
            else:
                console.print("[yellow]⚠[/yellow] No JSM connection – cannot fetch ticket.\n")
            continue
        if user_input.lower() == "/help":
            console.print(
                Panel(
                    "[bold]/new[/bold]          Clear conversation history\n"
                    "[bold]/ticket KEY[/bold]   Switch ticket context\n"
                    "[bold]/quit[/bold]         Exit chat",
                    title="Commands",
                    border_style="dim",
                    padding=(0, 2),
                )
            )
            continue

        history.append({"role": "user", "content": user_input})
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]

        with Progress(
            SpinnerColumn(),
            TextColumn("[dim]{task.description}[/dim]"),
            transient=True,
            console=console,
        ) as prog:
            t = prog.add_task("Thinking…", total=None)
            try:
                reply = engine.chat(history, ticket_context=ticket)
                prog.update(t, completed=True)
            except Exception as exc:
                prog.update(t, completed=True)
                console.print(f"[red]✗[/red] {exc}\n")
                continue

        history.append({"role": "assistant", "content": reply})
        console.print(
            Panel(
                Markdown(reply),
                title="[bold cyan]Assistant[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
        console.print()


def _chat_plain(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Fallback chat loop when prompt_toolkit is unavailable."""
    ticket: Optional[Ticket] = None
    if args.ticket and jsm:
        try:
            ticket = jsm.get_ticket(args.ticket)
            console.print(f"Context: [bold]{ticket.key}[/bold]  {ticket.summary}")
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow] {exc}")

    history: list[dict] = []
    MAX_HISTORY = 40

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break
        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit"):
            console.print("[dim]Goodbye.[/dim]")
            break

        history.append({"role": "user", "content": user_input})
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]
        try:
            reply = engine.chat(history, ticket_context=ticket)
            history.append({"role": "assistant", "content": reply})
            console.print(Panel(Markdown(reply), title="Assistant", border_style="cyan"))
            console.print()
        except Exception as exc:
            console.print(f"[red]✗[/red] {exc}\n")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jsm-triage",
        description="AI-powered JSM helpdesk ticket triage  (OAuth 2.0 + multi-provider AI)",
    )
    parser.add_argument(
        "--provider", "-p",
        metavar="NAME",
        help="Comma-separated provider order: azure_openai,github_copilot,openai,ms_copilot,rovo",
    )
    parser.add_argument("--dry-run", action="store_true", help="Analyse only – do not write to JSM")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show raw JSON responses")

    sub = parser.add_subparsers(dest="command")

    # auth
    auth = sub.add_parser("auth", help="OAuth 2.0 login / logout / status")
    auth.add_argument(
        "target",
        nargs="?",
        choices=["atlassian", "azure", "github", "logout", "status"],
        default="status",
        help="Provider to authenticate (default: status)",
    )
    auth.add_argument(
        "--provider-name",
        dest="logout_provider",
        metavar="PROVIDER",
        help="Provider to logout (used with 'logout')",
    )

    # status
    sub.add_parser("status", help="Show provider and JSM connection status")

    def _add_write_args(p):
        p.add_argument("--no-comment",      action="store_true", help="Do not post AI comment to ticket")
        p.add_argument("--no-label",        action="store_true", help="Do not add ai-triaged label")
        p.add_argument("--update-priority", action="store_true", help="Overwrite ticket priority field")

    # triage
    triage = sub.add_parser("triage", help="Triage one or more tickets")
    triage.add_argument("ticket_keys", nargs="*", metavar="TICKET", help="e.g. IT-42 IT-43")
    triage.add_argument("--service-desk", "-s", metavar="ID")
    triage.add_argument("--queue",        "-q", metavar="ID")
    triage.add_argument("--jql",                metavar="JQL",  help="JQL query to select tickets")
    triage.add_argument("--limit",        "-l", type=int, default=20)
    triage.add_argument("--output-json",        metavar="FILE", help="Save results as JSON file")
    _add_write_args(triage)

    # watch
    watch = sub.add_parser("watch", help="Watch a queue and auto-triage new tickets")
    watch.add_argument("--service-desk", "-s", metavar="ID", required=True)
    watch.add_argument("--queue",        "-q", metavar="ID", required=True)
    watch.add_argument("--interval",     "-i", type=int, default=60, help="Poll interval in seconds")
    watch.add_argument("--limit",        "-l", type=int, default=50)
    _add_write_args(watch)

    # chat
    chat = sub.add_parser("chat", help="Interactive chat (optionally anchored to a ticket)")
    chat.add_argument("--ticket", "-t", metavar="KEY", help="Ticket key for context (e.g. IT-42)")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "auth":
        cmd_auth(args)
        return

    preferred = [p.strip() for p in args.provider.split(",")] if args.provider else None

    from .providers.azure_openai import AzureOpenAIProvider
    from .providers.github_copilot import GitHubCopilotProvider
    from .providers.openai_direct import OpenAIProvider
    from .providers.ms_copilot import MSCopilotProvider
    from .providers.rovo import RovoProvider

    az_oauth = AzureOAuth(_token_store)
    gh_oauth = GitHubOAuth(_token_store)

    provider_instances = {
        "azure_openai":   AzureOpenAIProvider(azure_oauth=az_oauth),
        "github_copilot": GitHubCopilotProvider(github_oauth=gh_oauth),
        "openai":         OpenAIProvider(),
        "ms_copilot":     MSCopilotProvider(),
        "rovo":           RovoProvider(),
    }

    providers = build_provider_chain(preferred, instances=provider_instances)

    if not providers:
        console.print("[red]✗[/red] No AI providers configured.")
        console.print(
            "  Run [bold]jsm-triage auth atlassian/azure/github[/bold] "
            "or set API key env vars.\n"
            "  See [bold]jsm_triage/.env.example[/bold] for details."
        )
        sys.exit(1)

    engine = TriageEngine(
        providers=providers,
        dry_run=getattr(args, "dry_run", False),
    )

    jsm: Optional[JSMClient] = None
    atl_oauth = AtlassianOAuth(_token_store)
    try:
        if atl_oauth.is_configured() or os.getenv("ATLASSIAN_DOMAIN"):
            jsm = JSMClient(oauth=atl_oauth if atl_oauth.is_configured() else None)
    except Exception as exc:
        console.print(f"[yellow]⚠[/yellow] JSM client unavailable: {exc}")

    command_map = {
        "status": cmd_status,
        "triage": cmd_triage,
        "watch":  cmd_watch,
        "chat":   cmd_chat,
    }

    cmd_fn = command_map.get(args.command)
    if cmd_fn:
        cmd_fn(args, engine, jsm)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
