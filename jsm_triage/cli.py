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
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load .env from the project root or a jsm_triage/.env
_here = Path(__file__).parent
load_dotenv(_here / ".env")
load_dotenv(_here.parent / ".env")

from .triage_engine import TriageEngine, build_provider_chain
from .jsm.client import JSMClient
from .jsm.models import Ticket
from .providers.base import TriageResult
from .auth import AtlassianOAuth, AzureOAuth, GitHubOAuth, PROVIDER_LABELS
from .auth.token_store import TokenStore

# Shared token store instance for the whole process
_token_store = TokenStore()


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _print_banner():
    print("=" * 65)
    print("  JSM AI Triage Tool  –  Atlassian JSM + Multi-Provider AI")
    print("=" * 65)


def _print_result(ticket: Ticket, result: TriageResult, verbose: bool = False):
    p_color = {
        "Critical": "\033[91m",
        "High":     "\033[93m",
        "Medium":   "\033[94m",
        "Low":      "\033[92m",
    }.get(result.priority, "")
    reset = "\033[0m" if p_color else ""

    print(f"\n{'-'*55}")
    print(f"  Ticket : {ticket.key}  –  {ticket.summary[:55]}")
    print(f"  Provider : {result.provider_used}  ({result.confidence:.0%} confidence)")
    print(f"  Priority : {p_color}{result.priority}{reset}")
    print(f"  Category : {result.category} / {result.subcategory}")
    if result.suggested_team:
        print(f"  Team     : {result.suggested_team}")
    if result.suggested_assignee:
        print(f"  Assignee : {result.suggested_assignee}")
    if result.estimated_resolution:
        print(f"  Est. SLA : {result.estimated_resolution}")
    print(f"\n  Summary  : {result.summary}")
    if result.suggested_actions:
        print("  Actions  :")
        for i, action in enumerate(result.suggested_actions, 1):
            print(f"    {i}. {action}")
    if result.escalate:
        print(f"\n  \033[91m*** ESCALATE: {result.escalation_reason} ***\033[0m")
    if verbose:
        print(f"\n  Raw JSON :\n{result.raw_response}")


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_auth(args, *_):
    """Handle the 'auth' sub-command – OAuth 2.0 login for all providers."""
    target = getattr(args, "target", "status")

    def do_atlassian():
        oauth = AtlassianOAuth(_token_store)
        if not oauth.is_configured():
            print("  ATLASSIAN_CLIENT_ID and ATLASSIAN_CLIENT_SECRET must be set in .env")
            print("  See https://developer.atlassian.com/console/myapps/ to create an OAuth app")
            sys.exit(1)
        oauth.login()

    def do_azure():
        oauth = AzureOAuth(_token_store)
        if not oauth.is_configured():
            print("  AZURE_CLIENT_ID and AZURE_TENANT_ID must be set in .env")
            sys.exit(1)
        oauth.login()

    def do_github():
        oauth = GitHubOAuth(_token_store)
        if not oauth.is_configured():
            print("  GITHUB_CLIENT_ID must be set in .env")
            print("  See https://github.com/settings/developers to create an OAuth App")
            sys.exit(1)
        oauth.login()

    def do_logout():
        provider = getattr(args, "logout_provider", None)
        if provider:
            _token_store.clear(provider)
            print(f"  Logged out: {provider}")
        else:
            _token_store.clear_all()
            print("  Logged out all providers")

    def do_status():
        print("\n  Stored OAuth tokens:")
        for key, label in PROVIDER_LABELS:
            entry = _token_store.get(key)
            if entry:
                if _token_store.is_expired(key):
                    rt = _token_store.refresh_token(key)
                    state = "expired (refresh token available)" if rt else "expired – login again"
                else:
                    state = "valid"
                print(f"    ✅ {label}: {state}")
            else:
                print(f"    ⬜ {label}: not logged in")
        print()

    _print_banner()
    handlers = {
        "atlassian": do_atlassian,
        "azure":     do_azure,
        "github":    do_github,
        "logout":    do_logout,
        "status":    do_status,
    }
    fn = handlers.get(target, do_status)
    fn()


def cmd_status(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    _print_banner()

    _ALL_PROVIDER_NAMES = [
        "Azure OpenAI", "GitHub Copilot", "OpenAI (ChatGPT)",
        "Microsoft Copilot", "Atlassian Rovo",
    ]
    active_names = {p.name for p in engine.providers}
    print("\n  AI Providers:")
    for name in _ALL_PROVIDER_NAMES:
        status = "✅ configured" if name in active_names else "⬜ not configured"
        print(f"    {status}  {name}")

    print("\n  OAuth sessions (run 'jsm-triage auth status' for details):")
    for key, label in PROVIDER_LABELS:
        state = "logged in" if _token_store.get(key) and not _token_store.is_expired(key) else "not logged in"
        print(f"    {label}: {state}")

    print("\n  JSM Connection:")
    if jsm:
        try:
            url = jsm.test_connection()
            print(f"    ✅ Connected  –  {url}")
            desks = jsm.list_service_desks()
            for d in desks:
                print(f"       Service Desk: {d.name} (ID={d.id}, key={d.project_key})")
        except Exception as exc:
            print(f"    ❌ Connection failed: {exc}")
    else:
        print("    ⬜ Not configured (ATLASSIAN_DOMAIN not set, and no OAuth session)")
    print()


def cmd_triage(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    _print_banner()

    tickets: list[Ticket] = []

    if args.ticket_keys:
        if not jsm:
            print("❌ JSM credentials required to fetch tickets.")
            sys.exit(1)
        for key in args.ticket_keys:
            print(f"  Fetching {key}…")
            try:
                tickets.append(jsm.get_ticket(key))
            except Exception as exc:
                print(f"  ❌ Could not fetch {key}: {exc}")

    elif args.jql:
        if not jsm:
            print("❌ JSM credentials required for JQL search.")
            sys.exit(1)
        print(f"  Searching: {args.jql}")
        tickets = jsm.search_tickets(args.jql, limit=args.limit)

    elif args.service_desk and args.queue:
        if not jsm:
            print("❌ JSM credentials required to read queues.")
            sys.exit(1)
        print(f"  Fetching queue {args.queue} from service desk {args.service_desk}…")
        tickets = jsm.get_queue_tickets(args.service_desk, args.queue, limit=args.limit)

    else:
        try:
            key = input("  Enter ticket key (e.g. IT-42): ").strip()
            if not key:
                return
            if jsm:
                tickets.append(jsm.get_ticket(key))
            else:
                summary = input("  Summary: ").strip()
                description = input("  Description: ").strip()
                tickets.append(Ticket(
                    key=key, summary=summary, description=description,
                    status="Open", priority="Medium", issue_type="Service Request",
                    reporter="unknown", assignee=None,
                ))
        except (EOFError, KeyboardInterrupt):
            return

    if not tickets:
        print("  No tickets found.")
        return

    print(f"\n  Triaging {len(tickets)} ticket(s)…\n")
    results: list[tuple[Ticket, TriageResult]] = []

    for ticket in tickets:
        print(f"  Analysing {ticket.key}…", end=" ", flush=True)
        try:
            if jsm:
                # engine.dry_run controls whether writes happen
                result = engine.triage_and_apply(
                    ticket, jsm,
                    post_comment=not args.no_comment,
                    update_priority=args.update_priority,
                    add_triage_label=not args.no_label,
                )
            else:
                result = engine.triage_ticket(ticket)
            print("done")
            results.append((ticket, result))
            _print_result(ticket, result, verbose=args.verbose)
        except Exception as exc:
            print(f"failed\n  ❌ {exc}")

    if args.output_json:
        output = [{"ticket": t.key, "triage": r.to_dict()} for t, r in results]
        Path(args.output_json).write_text(json.dumps(output, indent=2))
        print(f"\n  Results written to {args.output_json}")

    print(f"\n  Done – triaged {len(results)}/{len(tickets)} tickets.")


def cmd_watch(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    if not jsm:
        print("❌ JSM credentials required for watch mode.")
        sys.exit(1)

    _print_banner()
    print(f"  Watching queue {args.queue} on service desk {args.service_desk}")
    print(f"  Polling every {args.interval}s  |  Ctrl-C to stop\n")

    seen: set[str] = set()
    SEEN_CAP = 10_000   # prevent unbounded growth in long-running watch sessions
    stop = [False]

    def _sigint(sig, frame):
        print("\n  Stopping watcher…")
        stop[0] = True

    signal.signal(signal.SIGINT, _sigint)

    while not stop[0]:
        try:
            tickets = jsm.get_queue_tickets(args.service_desk, args.queue, limit=args.limit)
            new_tickets = [t for t in tickets if t.key not in seen]

            if new_tickets:
                print(f"  {time.strftime('%H:%M:%S')} – {len(new_tickets)} new ticket(s)")
                for ticket in new_tickets:
                    seen.add(ticket.key)
                    if len(seen) > SEEN_CAP:
                        # Drop the oldest quarter to keep memory bounded
                        to_drop = list(seen)[:SEEN_CAP // 4]
                        seen.difference_update(to_drop)
                    print(f"    Triaging {ticket.key}…", end=" ", flush=True)
                    try:
                        engine.triage_and_apply(
                            ticket, jsm,
                            post_comment=not args.no_comment,
                            update_priority=args.update_priority,
                            add_triage_label=not args.no_label,
                        )
                        print("done")
                    except Exception as exc:
                        print(f"failed ({exc})")
            else:
                print(f"  {time.strftime('%H:%M:%S')} – no new tickets", end="\r")

        except Exception as exc:
            print(f"  ⚠️  Error polling queue: {exc}")

        time.sleep(args.interval)


def cmd_chat(args, engine: TriageEngine, jsm: Optional[JSMClient]):
    _print_banner()

    ticket: Optional[Ticket] = None
    if args.ticket and jsm:
        try:
            ticket = jsm.get_ticket(args.ticket)
            print(f"  Context: {ticket.key} – {ticket.summary}")
        except Exception as exc:
            print(f"  Warning: could not fetch ticket context: {exc}")

    provider_names = ", ".join(p.name for p in engine.providers)
    print(f"  Provider(s): {provider_names}")
    print("  Type 'quit' or Ctrl-C to exit\n")

    history: list[dict] = []
    MAX_HISTORY = 40  # keep last 40 messages (~20 turns) to avoid context overflow

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "bye"):
            print("Goodbye!")
            break

        history.append({"role": "user", "content": user_input})
        # Trim oldest pairs to stay within context limits
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]

        try:
            reply = engine.chat(history, ticket_context=ticket)
            history.append({"role": "assistant", "content": reply})
            print(f"\nAssistant: {reply}\n")
        except Exception as exc:
            print(f"\n❌ {exc}\n")


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
        help="Which provider to authenticate (default: status)",
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
        """Shared JSM write-back flags used by both triage and watch."""
        p.add_argument("--no-comment", action="store_true", help="Do not post AI comment to ticket")
        p.add_argument("--no-label", action="store_true", help="Do not add ai-triaged label")
        p.add_argument("--update-priority", action="store_true", help="Overwrite ticket priority field")

    # triage
    triage = sub.add_parser("triage", help="Triage one or more tickets")
    triage.add_argument("ticket_keys", nargs="*", metavar="TICKET", help="e.g. IT-42 IT-43")
    triage.add_argument("--service-desk", "-s", metavar="ID")
    triage.add_argument("--queue", "-q", metavar="ID")
    triage.add_argument("--jql", metavar="JQL", help="JQL query to select tickets")
    triage.add_argument("--limit", "-l", type=int, default=20)
    triage.add_argument("--output-json", metavar="FILE", help="Save results as JSON file")
    _add_write_args(triage)

    # watch
    watch = sub.add_parser("watch", help="Watch a queue and auto-triage new tickets")
    watch.add_argument("--service-desk", "-s", metavar="ID", required=True)
    watch.add_argument("--queue", "-q", metavar="ID", required=True)
    watch.add_argument("--interval", "-i", type=int, default=60, help="Poll interval in seconds")
    watch.add_argument("--limit", "-l", type=int, default=50)
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

    # Auth command doesn't need providers or JSM
    if args.command == "auth":
        cmd_auth(args)
        return

    # Build OAuth helpers, then pass pre-built provider instances so no
    # monkey-patching is needed.
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
        print("❌ No AI providers configured.")
        print("   Run 'jsm-triage auth atlassian/azure/github' or set API key env vars.")
        print("   See jsm_triage/.env.example for details.")
        sys.exit(1)

    engine = TriageEngine(
        providers=providers,
        dry_run=getattr(args, "dry_run", False),
    )

    # Build JSM client – prefer OAuth 2.0, fall back to basic auth
    jsm: Optional[JSMClient] = None
    atl_oauth = AtlassianOAuth(_token_store)
    try:
        if atl_oauth.is_configured() or os.getenv("ATLASSIAN_DOMAIN"):
            jsm = JSMClient(oauth=atl_oauth if atl_oauth.is_configured() else None)
    except Exception as exc:
        print(f"  Warning: JSM client unavailable: {exc}")

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
