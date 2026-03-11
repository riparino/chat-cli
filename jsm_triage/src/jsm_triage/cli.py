#!/usr/bin/env python3
"""
JSM AI Triage Tool – CLI entry point.

Modes:
  auth            – OAuth 2.0 login for Atlassian / Azure / GitHub
  triage          – triage one or more tickets (by key, JQL, or queue)
  watch           – continuously watch a queue and triage new tickets
  chat            – free-form chat with the AI (optionally anchored to a ticket)
  explain         – show detailed triage reasoning for a ticket
  feedback        – record a human outcome for a triaged ticket
  validate-config – validate local policy/config files
  knowledge-test  – test Confluence/Rovo knowledge retrieval
  export-examples – export approved feedback as triage examples
  review-rules    – show staged rule candidates for admin review
  status          – show configured providers and JSM connection info

Usage examples:
  jsm-triage auth atlassian
  jsm-triage triage IT-42
  jsm-triage triage --jql "project=IT AND status=Open AND labels!=ai-triaged"
  jsm-triage watch --queue 1 --service-desk 2 --interval 60
  jsm-triage explain IT-42
  jsm-triage feedback IT-42
  jsm-triage validate-config
  jsm-triage knowledge-test --query "urgent termination access removal"
  jsm-triage export-examples
  jsm-triage review-rules
  jsm-triage status
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

_here = Path(__file__).parent
load_dotenv(_here / ".env")
load_dotenv(_here.parent / ".env")

# Rich imports
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from .audit import AuditLog, configure_logging
from .feedback.store import FeedbackStore, OUTCOME_ACCEPTED, OUTCOME_CORRECTED, OUTCOME_REJECTED
from .triage_engine import TriageEngine, build_provider_chain
from .jsm.client import JSMClient
from .jsm.models import Ticket
from .providers.base import IAMTriageResult
from .auth import AtlassianOAuth, AzureOAuth, GitHubOAuth, PROVIDER_LABELS
from .auth.token_store import TokenStore

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

console = Console()
_token_store = TokenStore()

_PRIORITY_STYLE = {
    "Critical": ("bold white on dark_red",   "● Critical"),
    "High":     ("bold red",                  "● High"),
    "Medium":   ("bold yellow",               "● Medium"),
    "Low":      ("bold green",                "● Low"),
}

_NEXT_STEP_STYLE = {
    "Return for Info":  ("yellow",          "↩ Return for Info"),
    "Fulfill":          ("bold green",      "✓ Fulfill"),
    "Route to Team":    ("cyan",            "→ Route to Team"),
    "Escalate":         ("bold red",        "⚡ Escalate"),
    "Reject":           ("bold red",        "✗ Reject"),
    "Pending Approval": ("bold yellow",     "⏸ Pending Approval"),
}

_ALL_PROVIDER_NAMES = [
    "Azure OpenAI",
    "GitHub Copilot",
    "OpenAI (ChatGPT)",
    "Microsoft Copilot",
    "Atlassian Rovo",
]


# ---------------------------------------------------------------------------
# Context manager helpers
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
            "[dim]IAM/Access Management Edition[/dim]",
            box=box.DOUBLE_EDGE,
            padding=(0, 4),
            style="bold",
        )
    )


def _priority_text(priority: str) -> Text:
    style, label = _PRIORITY_STYLE.get(priority, ("bold white", f"● {priority}"))
    return Text(label, style=style)


def _next_step_text(next_step: str) -> Text:
    style, label = _NEXT_STEP_STYLE.get(next_step, ("white", next_step))
    return Text(label, style=style)


def _render_result(ticket: Ticket, result: IAMTriageResult, verbose: bool = False):
    """Render a triage result as a rich Panel."""
    border_color = {
        "Critical": "dark_red",
        "High":     "red",
        "Medium":   "yellow",
        "Low":      "green",
    }.get(result.priority, "cyan")

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", min_width=20)
    grid.add_column()

    grid.add_row("Provider", f"{result.provider_used}  [dim]({result.confidence:.0%} confidence)[/dim]")
    grid.add_row("Priority", _priority_text(result.priority))
    grid.add_row(
        "Urgency / Impact",
        f"{result.urgency} / {result.business_impact}"
    )
    grid.add_row("Category", f"{result.category}[dim] / {result.subcategory}[/dim]")
    grid.add_row("Request Type", result.request_type or "[dim]—[/dim]")
    if result.likely_fulfilling_team:
        grid.add_row("Suggested Team", result.likely_fulfilling_team)
    if result.likely_assignment_group:
        grid.add_row("Assignment Group", result.likely_assignment_group)

    grid.add_row("", "")
    grid.add_row("Next Step", _next_step_text(result.recommended_next_step))

    if result.requires_approval:
        grid.add_row(
            "Approval Required",
            Text(f"⚠ {result.approval_type or 'Yes'}", style="bold yellow"),
        )

    if result.required_information_missing and result.missing_fields:
        missing_text = Text()
        for f in result.missing_fields:
            missing_text.append(f"  • {f}\n", style="yellow")
        grid.add_row("Missing Info", missing_text)

    grid.add_row("", "")
    grid.add_row("Rationale", Text(result.rationale or "—", overflow="fold"))

    if result.suggested_actions:
        actions_text = Text()
        for i, action in enumerate(result.suggested_actions, 1):
            actions_text.append(f"  {i}. {action}\n")
        grid.add_row("Actions", actions_text)

    if result.escalation_required:
        grid.add_row(
            "",
            Text(
                f"⚡ ESCALATE: {result.escalation_reason}",
                style="bold white on dark_red",
            ),
        )

    if result.policy_references:
        grid.add_row("Policy Refs", "\n".join(f"  • {r}" for r in result.policy_references))

    if result.knowledge_sources_used:
        grid.add_row(
            "Knowledge Used",
            "[dim]" + ", ".join(result.knowledge_sources_used[:3]) + "[/dim]",
        )

    title = f"[bold]{ticket.key}[/bold]  [dim]·[/dim]  {ticket.summary[:70]}"
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

    # Config / grounding status
    config_loader = engine._policy_loader
    policy = config_loader.load()
    config_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    config_table.add_column(min_width=22)
    config_table.add_column()
    config_table.add_row("Config dir", str(config_loader.config_dir()))
    config_table.add_row("Routing rules", str(len(policy.routing_rules)))
    config_table.add_row("Approval rules", str(len(policy.approval_rules)))
    config_table.add_row("Triage examples", str(len(policy.examples)))
    gs = config_loader.load_grounding_sources()
    config_table.add_row(
        "Confluence grounding",
        "[green]configured[/green]" if (gs.spaces or gs.page_ids or gs.cql_queries)
        else "[dim]not configured[/dim]",
    )
    console.print(Panel(config_table, title="Local Config / Grounding", padding=(0, 1)))

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
    results: list[tuple[Ticket, IAMTriageResult]] = []

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
                    ns_style, ns_label = _NEXT_STEP_STYLE.get(
                        result.recommended_next_step,
                        ("white", result.recommended_next_step),
                    )
                    console.print(
                        f"  [bold]{ticket.key}[/bold]  "
                        f"[{p_style}]{p_label}[/{p_style}]  "
                        f"[{ns_style}]{ns_label}[/{ns_style}]  "
                        f"[dim]{result.category}[/dim]"
                    )
            else:
                console.print(
                    f"[dim]{time.strftime('%H:%M:%S')}  no new tickets[/dim]",
                    end="\r",
                )

        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow] Error polling queue: {exc}")

        time.sleep(args.interval)


def cmd_explain(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Show detailed triage reasoning for a previously triaged ticket."""
    _banner()

    if not jsm:
        console.print("[red]✗[/red] JSM credentials required to fetch ticket.")
        sys.exit(1)

    key = args.ticket_key
    with _spinner(f"Fetching [bold]{key}[/bold]…"):
        try:
            ticket = jsm.get_ticket(key)
        except Exception as exc:
            console.print(f"[red]✗[/red] Could not fetch {key}: {exc}")
            sys.exit(1)

    console.print(f"\n[bold]Re-triaging {key} for explanation…[/bold]\n")

    with _spinner(f"Analysing [bold]{key}[/bold]…"):
        try:
            result = engine.triage_ticket(ticket)
        except Exception as exc:
            console.print(f"[red]✗[/red] Triage failed: {exc}")
            sys.exit(1)

    _render_result(ticket, result, verbose=True)

    # Show full explanation panel
    explain_grid = Table.grid(padding=(0, 2))
    explain_grid.add_column(style="bold cyan", min_width=28)
    explain_grid.add_column()

    explain_grid.add_row("Confidence", f"{result.confidence:.0%}")
    explain_grid.add_row("Rationale", Text(result.rationale or "—", overflow="fold"))

    if result.missing_fields:
        explain_grid.add_row(
            "Missing Information",
            "\n".join(f"• {f}" for f in result.missing_fields),
        )

    if result.policy_references:
        explain_grid.add_row(
            "Policy References",
            "\n".join(f"• {r}" for r in result.policy_references),
        )

    if result.knowledge_sources_used:
        explain_grid.add_row(
            "Knowledge Sources Used",
            "\n".join(f"• {s}" for s in result.knowledge_sources_used),
        )

    explain_grid.add_row("Provider Used", result.provider_used)

    console.print(Panel(
        explain_grid,
        title="[bold]Triage Explanation[/bold]",
        border_style="cyan",
        padding=(1, 2),
    ))

    if args.output_json:
        Path(args.output_json).write_text(
            json.dumps(result.to_dict(), indent=2), encoding="utf-8"
        )
        console.print(f"\n[green]✓[/green] Explanation JSON written to [bold]{args.output_json}[/bold]")


def cmd_feedback(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Record a human outcome for a triaged ticket."""
    _banner()

    store = FeedbackStore()
    key = args.ticket_key

    # Show any existing triage record for this ticket
    existing = store.get_records_for_ticket(key)
    if existing:
        console.print(f"\n[dim]Found {len(existing)} existing record(s) for {key}[/dim]\n")
    else:
        console.print(f"\n[yellow]No existing triage record found for {key}.[/yellow]")
        console.print("[dim]Recording feedback without a prior triage record.[/dim]\n")

    # Determine outcome
    outcome = getattr(args, "outcome", None)
    if outcome is None:
        console.print("Outcome options:")
        console.print("  [green]accepted[/green]   – AI triage was correct")
        console.print("  [yellow]corrected[/yellow]  – AI triage needed corrections")
        console.print("  [red]rejected[/red]   – AI triage was wrong/unhelpful")
        try:
            outcome = console.input("\n[cyan]Outcome[/cyan]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return

    if outcome not in (OUTCOME_ACCEPTED, OUTCOME_CORRECTED, OUTCOME_REJECTED):
        console.print(f"[red]✗[/red] Invalid outcome '{outcome}'")
        sys.exit(1)

    correction = None
    if outcome == OUTCOME_CORRECTED:
        console.print("\n[dim]Enter corrected values (press Enter to skip a field):[/dim]")
        correction = {}
        for field_name in ["category", "subcategory", "priority", "recommended_next_step"]:
            try:
                val = console.input(f"  [cyan]{field_name}[/cyan]: ").strip()
                if val:
                    correction[field_name] = val
            except (EOFError, KeyboardInterrupt):
                break

    approved_as_example = False
    if outcome in (OUTCOME_ACCEPTED, OUTCOME_CORRECTED):
        try:
            ans = console.input(
                "\nApprove as grounding example for future triage? [y/N]: "
            ).strip().lower()
            approved_as_example = ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            pass

    example_tags: list[str] = []
    if approved_as_example:
        try:
            tags_input = console.input("Tags (comma-separated, e.g. onboarding,github): ").strip()
            if tags_input:
                example_tags = [t.strip() for t in tags_input.split(",") if t.strip()]
        except (EOFError, KeyboardInterrupt):
            pass

    notes = None
    try:
        notes = console.input("\nReviewer notes (optional, Enter to skip): ").strip() or None
    except (EOFError, KeyboardInterrupt):
        pass

    store.record_outcome(
        ticket_key=key,
        outcome=outcome,
        correction=correction,
        reviewer_notes=notes,
        approved_as_example=approved_as_example,
        example_tags=example_tags,
    )

    outcome_styles = {
        OUTCOME_ACCEPTED: "[green]accepted[/green]",
        OUTCOME_CORRECTED: "[yellow]corrected[/yellow]",
        OUTCOME_REJECTED: "[red]rejected[/red]",
    }
    console.print(
        f"\n[green]✓[/green] Feedback recorded: {key} → {outcome_styles[outcome]}"
    )
    if approved_as_example:
        console.print(
            f"  [dim]Approved as example. Run [bold]jsm-triage export-examples[/bold] "
            f"to export to config/.[/dim]"
        )


def cmd_validate_config(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Validate local policy/config files."""
    _banner()

    console.print("[bold]Validating configuration…[/bold]\n")

    issues = engine.validate_config()

    config_dir = engine._policy_loader.config_dir()
    console.print(f"Config directory: [bold]{config_dir}[/bold]")

    policy = engine._policy_loader.load()
    gs = engine._policy_loader.load_grounding_sources()

    # Summary table
    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    table.add_column("Item", style="bold")
    table.add_column("Status")
    table.add_column("Count / Value")

    def _check_row(name: str, count: int, warn_if_zero: bool = True):
        if count > 0:
            table.add_row(name, "[green]✓ loaded[/green]", str(count))
        elif warn_if_zero:
            table.add_row(name, "[yellow]⚠ empty[/yellow]", "0")
        else:
            table.add_row(name, "[dim]—[/dim]", "0")

    _check_row("Routing rules", len(policy.routing_rules))
    _check_row("Approval rules", len(policy.approval_rules))
    _check_row("Triage examples", len(policy.examples))
    _check_row("Confluence spaces", len(gs.spaces), warn_if_zero=False)
    _check_row("Confluence page IDs", len(gs.page_ids), warn_if_zero=False)
    _check_row("CQL queries", len(gs.cql_queries), warn_if_zero=False)
    _check_row("AI providers", len(engine.providers))

    console.print(table)

    if issues:
        console.print(f"\n[yellow]⚠ {len(issues)} issue(s) found:[/yellow]")
        for issue in issues:
            console.print(f"  [yellow]·[/yellow] {issue}")
        sys.exit(1)
    else:
        console.print("\n[green]✓ Configuration is valid.[/green]")


def cmd_knowledge_test(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Test knowledge retrieval with a query string."""
    _banner()

    query = args.query
    console.print(f"[bold]Testing knowledge retrieval:[/bold] {query}\n")

    with _spinner("Querying knowledge sources…"):
        results = engine.test_knowledge_retrieval(query)

    # Summary
    summary_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    summary_table.add_column(min_width=28)
    summary_table.add_column()

    def _bool_status(val: bool) -> str:
        return "[green]✓ available[/green]" if val else "[dim]not available[/dim]"

    summary_table.add_row("Confluence retriever", _bool_status(results["confluence_available"]))
    summary_table.add_row("Rovo retriever", _bool_status(results["rovo_available"]))
    summary_table.add_row("Local policy", _bool_status(results["local_policy_available"]))
    summary_table.add_row("Routing rules", str(results["local_routing_rules_count"]))
    summary_table.add_row("Approval rules", str(results["local_approval_rules_count"]))
    summary_table.add_row("Local examples", str(results["local_examples_count"]))
    summary_table.add_row("Snippets retrieved", str(len(results["snippets"])))
    console.print(Panel(summary_table, title="Knowledge Sources", padding=(0, 1)))

    if results["snippets"]:
        console.print("\n[bold]Retrieved Snippets:[/bold]\n")
        for i, snippet in enumerate(results["snippets"], 1):
            title = snippet["title"]
            source_type = snippet.get("source_type", "unknown")
            url = snippet.get("source_url") or ""
            preview = snippet.get("content_preview", "")
            console.print(
                Panel(
                    f"[dim]{preview}[/dim]",
                    title=f"[bold]{i}. {title}[/bold]  [dim]({source_type})[/dim]"
                    + (f"  {url}" if url else ""),
                    border_style="dim",
                    padding=(0, 1),
                )
            )
    else:
        console.print("[yellow]No knowledge snippets retrieved.[/yellow]")

    if results["matching_examples"]:
        console.print("\n[bold]Matching Local Examples:[/bold]")
        for ex in results["matching_examples"]:
            console.print(
                f"  [cyan]{ex['key']}[/cyan]  {ex['summary'][:60]}  "
                f"[dim]({ex['category']})[/dim]"
            )


def cmd_export_examples(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Export approved feedback examples to a JSONL file."""
    _banner()

    store = FeedbackStore()
    stats = store.get_statistics()

    console.print(
        f"Feedback store: {stats['total_triaged']} triaged, "
        f"{stats['total_outcomes_recorded']} outcomes recorded, "
        f"{stats['approved_examples']} approved examples\n"
    )

    output_path = Path(args.output) if args.output else None

    with _spinner("Exporting approved examples…"):
        count, path = store.export_examples_jsonl(output_path)

    if count == 0:
        console.print("[yellow]No approved examples to export.[/yellow]")
        console.print(
            "[dim]Use [bold]jsm-triage feedback <TICKET>[/bold] and approve "
            "tickets as examples first.[/dim]"
        )
        return

    console.print(
        f"[green]✓[/green] Exported [bold]{count}[/bold] example(s) to [bold]{path}[/bold]"
    )
    console.print(
        f"\n[dim]To use these examples for grounding, copy this file to your "
        f"config directory as [bold]triage_examples.jsonl[/bold].[/dim]"
    )


def cmd_review_rules(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    """Show staged candidate rules pending admin review."""
    _banner()

    store = FeedbackStore()
    staged = store.get_staged_rules()

    if not staged:
        console.print("[dim]No staged rules pending review.[/dim]")
        return

    console.print(
        f"[bold]{len(staged)} staged rule candidate(s) pending admin review:[/bold]\n"
    )
    console.print(
        "[yellow]⚠ These are suggestions only. Review carefully before adding "
        "to config files.[/yellow]\n"
    )

    for i, rule in enumerate(staged, 1):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", min_width=18)
        grid.add_column()
        grid.add_row("Type", rule.get("rule_type", "unknown"))
        grid.add_row("Status", rule.get("status", ""))
        grid.add_row("Suggested", json.dumps(rule.get("suggested_rule", {}), indent=2))
        grid.add_row("Supporting tickets", ", ".join(rule.get("supporting_tickets", [])))
        grid.add_row("Notes", rule.get("notes", ""))
        grid.add_row("Staged at", rule.get("timestamp", ""))

        console.print(Panel(
            grid,
            title=f"[bold]Candidate {i}[/bold]",
            border_style="yellow",
            padding=(0, 1),
        ))

    console.print(
        f"\n[dim]To apply: manually add approved rules to your config files "
        f"in [bold]{engine._policy_loader.config_dir()}[/bold][/dim]"
    )


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

    session = PromptSession(
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
        description=(
            "AI-powered JSM ticket triage for IAM/access management  "
            "(OAuth 2.0 + multi-provider AI + Confluence grounding)"
        ),
    )
    parser.add_argument(
        "--provider", "-p",
        metavar="NAME",
        help="Comma-separated provider order: azure_openai,github_copilot,openai,ms_copilot,rovo",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Analyse only – do not write to JSM")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show raw JSON responses and debug info")
    parser.add_argument("--config-dir", metavar="PATH",
                        help="Path to policy config directory (overrides TRIAGE_CONFIG_DIR)")
    parser.add_argument("--redact", action="store_true",
                        help="Redact PII fields (reporter/assignee/description) before sending to AI")
    parser.add_argument("--no-confluence", action="store_true",
                        help="Disable Confluence knowledge retrieval")
    parser.add_argument("--rovo-grounding", action="store_true",
                        help="Enable Rovo-based knowledge retrieval (requires Rovo licence)")

    sub = parser.add_subparsers(dest="command")

    # auth
    auth = sub.add_parser("auth", help="OAuth 2.0 login / logout / status")
    auth.add_argument(
        "target",
        nargs="?",
        choices=["atlassian", "azure", "github", "logout", "status"],
        default="status",
    )
    auth.add_argument("--provider-name", dest="logout_provider", metavar="PROVIDER")

    # status
    sub.add_parser("status", help="Show provider, config, and JSM connection status")

    def _add_write_args(p):
        p.add_argument("--no-comment",      action="store_true",
                       help="Do not post AI comment to ticket")
        p.add_argument("--no-label",        action="store_true",
                       help="Do not add ai-triaged label")
        p.add_argument("--update-priority", action="store_true",
                       help="Overwrite ticket priority (use with caution)")

    # triage
    triage = sub.add_parser("triage", help="Triage one or more tickets")
    triage.add_argument("ticket_keys", nargs="*", metavar="TICKET")
    triage.add_argument("--service-desk", "-s", metavar="ID")
    triage.add_argument("--queue",        "-q", metavar="ID")
    triage.add_argument("--jql",                metavar="JQL")
    triage.add_argument("--limit",        "-l", type=int, default=20)
    triage.add_argument("--output-json",        metavar="FILE",
                        help="Save triage results as JSON")
    _add_write_args(triage)

    # watch
    watch = sub.add_parser("watch", help="Watch a queue and auto-triage new tickets")
    watch.add_argument("--service-desk", "-s", metavar="ID", required=True)
    watch.add_argument("--queue",        "-q", metavar="ID", required=True)
    watch.add_argument("--interval",     "-i", type=int, default=60,
                       help="Poll interval in seconds (default: 60)")
    watch.add_argument("--limit",        "-l", type=int, default=50)
    _add_write_args(watch)

    # explain
    explain = sub.add_parser("explain",
                              help="Show detailed triage reasoning for a ticket")
    explain.add_argument("ticket_key", metavar="TICKET")
    explain.add_argument("--output-json", metavar="FILE",
                         help="Save explanation JSON to file")

    # feedback
    feedback = sub.add_parser("feedback",
                               help="Record a human outcome for a triaged ticket")
    feedback.add_argument("ticket_key", metavar="TICKET")
    feedback.add_argument(
        "--outcome",
        choices=["accepted", "corrected", "rejected"],
        help="Outcome (skips interactive prompt)",
    )

    # validate-config
    sub.add_parser("validate-config", help="Validate local policy configuration files")

    # knowledge-test
    kt = sub.add_parser("knowledge-test",
                        help="Test Confluence/Rovo knowledge retrieval")
    kt.add_argument("--query", "-q", required=True,
                    help='Search query, e.g. "urgent termination access removal"')

    # export-examples
    export = sub.add_parser("export-examples",
                             help="Export approved feedback as triage examples JSONL")
    export.add_argument("--output", "-o", metavar="FILE",
                        help="Output file path (default: ~/.jsm_triage/exported_examples.jsonl)")

    # review-rules
    sub.add_parser("review-rules",
                   help="Show staged candidate routing/approval rules for admin review")

    # chat
    chat = sub.add_parser("chat", help="Interactive chat (optionally anchored to a ticket)")
    chat.add_argument("--ticket", "-t", metavar="KEY")

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

    # Configure logging early
    configure_logging(verbose=getattr(args, "verbose", False))

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

    # Commands that don't require AI providers
    no_provider_commands = {"validate-config", "export-examples", "review-rules", "feedback"}
    if not providers and args.command not in no_provider_commands:
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
        config_dir=getattr(args, "config_dir", None),
        enable_confluence_grounding=not getattr(args, "no_confluence", False),
        enable_rovo_grounding=getattr(args, "rovo_grounding", False),
        redact_sensitive=getattr(args, "redact", False),
    )

    jsm: Optional[JSMClient] = None
    atl_oauth = AtlassianOAuth(_token_store)
    try:
        if atl_oauth.is_configured() or os.getenv("ATLASSIAN_DOMAIN"):
            jsm = JSMClient(oauth=atl_oauth if atl_oauth.is_configured() else None)
    except Exception as exc:
        console.print(f"[yellow]⚠[/yellow] JSM client unavailable: {exc}")

    command_map = {
        "status":          cmd_status,
        "triage":          cmd_triage,
        "watch":           cmd_watch,
        "explain":         cmd_explain,
        "feedback":        cmd_feedback,
        "validate-config": cmd_validate_config,
        "knowledge-test":  cmd_knowledge_test,
        "export-examples": cmd_export_examples,
        "review-rules":    cmd_review_rules,
        "chat":            cmd_chat,
    }

    cmd_fn = command_map.get(args.command)
    if cmd_fn:
        cmd_fn(args, engine, jsm)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
