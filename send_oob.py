r"""Out-of-band Gmail sender — last-resort fallback when the live MCP server is wedged.

The MCP server is a long-running stdio child of Claude Desktop. If its in-memory
auth/transport state stalls (e.g. a token refresh that hung before the timeout fix),
every `send-email` MCP call returns -32001 and nothing is delivered, and the server
cannot be reloaded mid-session. This script runs the SAME GmailService code in a fresh
short-lived process with the on-disk token, so a routine can still deliver mail without
a Claude Desktop restart.

Usage (PowerShell):
  $env:PYTHONPATH="D:\MCP\gmail-mcp-server\src"
  & "D:\MCP\gmail-mcp-server\.venv\Scripts\python.exe" `
      "D:\MCP\gmail-mcp-server\send_oob.py" `
      --to petr@fucikovsky.cz --subject "Daily report 2026-06-02" --body-file body.html [--plain]

Body is read from --body-file (UTF-8). HTML is auto-detected; --plain forces plain text.
Prints "OK <message_id>" on success (exit 0) or "ERROR <msg>" (exit 1).
"""
import argparse
import asyncio
import sys

DEFAULT_CREDS = r"C:\Users\petr\.gmail-mcp\gcp-oauth.keys.json"
DEFAULT_TOKEN = r"C:\Users\petr\.gmail-mcp\token.json"


async def _run(args) -> int:
    from gmail.server import GmailService  # requires PYTHONPATH=.../src
    with open(args.body_file, encoding="utf-8") as fh:
        body = fh.read()
    svc = GmailService(args.creds, args.token)
    html = False if args.plain else None  # None => auto-detect from body
    res = await svc.send_email(args.to, args.subject, body, html)
    if res.get("status") == "success":
        print("OK " + res["message_id"])
        return 0
    print("ERROR " + str(res.get("error_message")))
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description="Out-of-band Gmail sender")
    p.add_argument("--to", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--body-file", required=True)
    p.add_argument("--plain", action="store_true", help="force plain text (default: auto-detect HTML)")
    p.add_argument("--creds", default=DEFAULT_CREDS)
    p.add_argument("--token", default=DEFAULT_TOKEN)
    args = p.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
