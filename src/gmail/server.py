from typing import Any
import argparse
import os
import sys
import asyncio
import logging
import base64
import re
from html import unescape
from email.message import EmailMessage
from email.header import decode_header
from base64 import urlsafe_b64decode
from email import message_from_bytes
import webbrowser

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio


import httplib2
import google_auth_httplib2
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _force_utf8_stdio() -> None:
    """Force UTF-8 on the stdio streams the MCP transport reads/writes.

    The MCP stdio transport (mcp.server.stdio.stdio_server) wraps the *text-mode*
    ``sys.stdin`` / ``sys.stdout`` directly. On Windows those default to the ANSI
    locale codepage (cp1250 on a Czech machine), so incoming UTF-8 JSON-RPC is
    decoded as cp1250 and every non-ASCII char in `message` arrives as mojibake
    (e.g. ``é`` -> ``Ă©``, ``ř`` -> ``Ĺ™``, ``°`` -> ``Â°``). The server then
    faithfully UTF-8-encodes that mojibake, so the delivered email is corrupted.
    Reconfiguring to UTF-8 *before* stdio_server() wraps the streams makes the
    whole transport decode/encode as UTF-8 regardless of the OS locale.
    """
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError) as exc:
            logger.warning("Could not force UTF-8 on %s: %s", stream, exc)


# Telltale substrings produced when UTF-8 text is decoded as cp1250 (Czech Windows
# locale). These never occur in correct Czech text, so their presence is a reliable
# signal that the body arrived mojibake'd over a non-UTF-8 stdio transport.
_MOJIBAKE_MARKERS = ("Ă", "Ĺ", "Ä›", "ÄŤ", "Â°", "â€", "Ĺˇ", "Ĺľ", "Ĺ™", "ĂŻ")


def _repair_cp1250_mojibake(text: str) -> str:
    """Detect and reverse 'UTF-8 decoded as cp1250' mojibake.

    Safety net / back-check for the stdin-encoding bug: if the body still arrives
    corrupted (e.g. server running before the UTF-8 stdio fix took effect), recover
    the original text by re-encoding to cp1250 and decoding as UTF-8. Bails out
    (returns the input unchanged) if the string has no mojibake markers or cannot be
    round-tripped — so correct text is never altered.
    """
    if not text or not any(m in text for m in _MOJIBAKE_MARKERS):
        return text
    try:
        repaired = text.encode("cp1250").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text  # not this mojibake pattern; leave untouched
    if repaired != text:
        logger.warning("Repaired cp1250 mojibake in outgoing body (transport was not UTF-8).")
    return repaired

# Network safety: without an explicit socket timeout the underlying httplib2
# transport can block forever (stalled TLS/DNS, hung token refresh). The MCP
# client then reports a -32001 timeout while the request is still in flight and
# the email may silently never be sent. GMAIL_HTTP_TIMEOUT bounds each socket
# operation; GMAIL_CALL_TIMEOUT is an outer asyncio backstop so the tool always
# returns a clean error well before the MCP client's own timeout fires.
GMAIL_HTTP_TIMEOUT = 30   # seconds, per socket op
GMAIL_CALL_TIMEOUT = 45   # seconds, outer guard around a single API call

EMAIL_ADMIN_PROMPTS = """You are an email administrator. 
You can draft, edit, read, trash, open, and send emails.
You've been given access to a specific gmail account. 
You have the following tools available:
- Send an email (send-email)
- Retrieve unread emails (get-unread-emails)
- Read email content (read-email)
- Trash email (tras-email)
- Open email in browser (open-email)
Never send an email draft or trash an email unless the user confirms first. 
Always ask for approval if not already given.
"""

# Define available prompts
PROMPTS = {
    "manage-email": types.Prompt(
        name="manage-email",
        description="Act like an email administator",
        arguments=None,
    ),
    "draft-email": types.Prompt(
        name="draft-email",
        description="Draft an email with cotent and recipient",
        arguments=[
            types.PromptArgument(
                name="content",
                description="What the email is about",
                required=True
            ),
            types.PromptArgument(
                name="recipient",
                description="Who should the email be addressed to",
                required=True
            ),
            types.PromptArgument(
                name="recipient_email",
                description="Recipient's email address",
                required=True
            ),
        ],
    ),
    "edit-draft": types.Prompt(
        name="edit-draft",
        description="Edit the existing email draft",
        arguments=[
            types.PromptArgument(
                name="changes",
                description="What changes should be made to the draft",
                required=True
            ),
            types.PromptArgument(
                name="current_draft",
                description="The current draft to edit",
                required=True
            ),
        ],
    ),
}


def decode_mime_header(header: str) -> str: 
    """Helper function to decode encoded email headers"""
    
    decoded_parts = decode_header(header)
    decoded_string = ''
    for part, encoding in decoded_parts: 
        if isinstance(part, bytes): 
            # Decode bytes to string using the specified encoding 
            decoded_string += part.decode(encoding or 'utf-8') 
        else: 
            # Already a string 
            decoded_string += part 
    return decoded_string


class GmailService:
    def __init__(self,
                 creds_file_path: str,
                 token_path: str,
                 scopes: list[str] = ['https://www.googleapis.com/auth/gmail.modify']):
        logger.info(f"Initializing GmailService with creds file: {creds_file_path}")
        self.creds_file_path = creds_file_path
        self.token_path = token_path
        self.scopes = scopes
        self.token = self._get_token()
        logger.info("Token retrieved successfully")
        self.service = self._get_service()
        logger.info("Gmail service initialized")
        self.user_email = self._get_user_email()
        logger.info(f"User email retrieved: {self.user_email}")

    def _get_token(self) -> Credentials:
        """Get or refresh Google API token"""

        token = None
    
        if os.path.exists(self.token_path):
            logger.info('Loading token from file')
            token = Credentials.from_authorized_user_file(self.token_path, self.scopes)

        if not token or not token.valid:
            if token and token.expired and token.refresh_token:
                logger.info('Refreshing token')
                token.refresh(Request())
            else:
                logger.info('Fetching new token')
                flow = InstalledAppFlow.from_client_secrets_file(self.creds_file_path, self.scopes)
                token = flow.run_local_server(port=0)

            with open(self.token_path, 'w') as token_file:
                token_file.write(token.to_json())
                logger.info(f'Token saved to {self.token_path}')

        return token

    def _get_service(self) -> Any:
        """Initialize Gmail API service"""
        try:
            # Wrap the credentials in an HTTP transport with an explicit socket
            # timeout. AuthorizedHttp also performs token refreshes over this
            # same (timed) transport, so neither a normal request nor a refresh
            # can hang indefinitely.
            authed_http = google_auth_httplib2.AuthorizedHttp(
                self.token, http=httplib2.Http(timeout=GMAIL_HTTP_TIMEOUT)
            )
            service = build('gmail', 'v1', http=authed_http)
            return service
        except HttpError as error:
            logger.error(f'An error occurred building Gmail service: {error}')
            raise ValueError(f'An error occurred: {error}')
    
    def _get_user_email(self) -> str:
        """Get user email address"""
        profile = self.service.users().getProfile(userId='me').execute()
        user_email = profile.get('emailAddress', '')
        return user_email
    
    async def send_draft(self, draft_id: str) -> dict:
        """Sends an existing Gmail draft by its draft ID"""
        try:
            send_message = await asyncio.wait_for(
                asyncio.to_thread(
                    self.service.users().drafts().send(userId="me", body={'id': draft_id}).execute
                ),
                timeout=GMAIL_CALL_TIMEOUT,
            )
            logger.info(f"Draft sent: {send_message['id']}")
            return {"status": "success", "message_id": send_message["id"]}
        except asyncio.TimeoutError:
            logger.error(f"send_draft timed out after {GMAIL_CALL_TIMEOUT}s")
            return {"status": "error", "error_message": f"timeout after {GMAIL_CALL_TIMEOUT}s (draft not sent)"}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
        except Exception as error:
            logger.error(f"send_draft failed: {error}")
            return {"status": "error", "error_message": str(error)}

    @staticmethod
    def _looks_like_html(text: str) -> bool:
        """Heuristic: does this body look like HTML (so it should be sent as text/html)?"""
        stripped = text.lstrip()
        if not stripped.startswith('<'):
            return False
        return re.search(
            r'(?i)<(?:html|body|div|p|table|tr|td|ul|ol|li|h[1-6]|br|span|a|strong|em|b|i)\b',
            stripped,
        ) is not None

    @staticmethod
    def _html_to_text(html_body: str) -> str:
        """Best-effort plaintext rendering of an HTML body, for the multipart fallback part."""
        text = re.sub(r'(?is)<(script|style).*?</\1>', '', html_body)
        text = re.sub(r'(?i)<br\s*/?>', '\n', text)
        text = re.sub(r'(?i)<li[^>]*>', '\n - ', text)
        text = re.sub(r'(?i)</(p|div|h[1-6]|li|tr|ul|ol)>', '\n', text)
        text = re.sub(r'<[^>]+>', '', text)
        text = unescape(text)
        text = re.sub(r'[ \t]+\n', '\n', text)
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()

    async def send_email(self, recipient_id: str, subject: str, message: str,
                         html: bool | None = None) -> dict:
        """Creates and sends an email message.

        Sends the body as HTML (multipart/alternative with a plaintext fallback) when
        `html` is True, or when `html` is None and the body looks like HTML. Otherwise
        sends as plain text. All parts are encoded as UTF-8.
        """
        try:
            # Back-check: recover any cp1250 mojibake before building the MIME message.
            message = _repair_cp1250_mojibake(message)
            subject = _repair_cp1250_mojibake(subject)

            send_as_html = html if html is not None else self._looks_like_html(message)

            message_obj = EmailMessage()
            message_obj['To'] = recipient_id
            message_obj['From'] = self.user_email
            message_obj['Subject'] = subject

            if send_as_html:
                message_obj.set_content(self._html_to_text(message), charset='utf-8')
                message_obj.add_alternative(message, subtype='html', charset='utf-8')
            else:
                message_obj.set_content(message, charset='utf-8')

            encoded_message = base64.urlsafe_b64encode(message_obj.as_bytes()).decode()
            create_message = {'raw': encoded_message}

            send_message = await asyncio.wait_for(
                asyncio.to_thread(
                    self.service.users().messages().send(userId="me", body=create_message).execute
                ),
                timeout=GMAIL_CALL_TIMEOUT,
            )
            logger.info(f"Message sent: {send_message['id']}")
            return {"status": "success", "message_id": send_message["id"]}
        except asyncio.TimeoutError:
            logger.error(f"send_email timed out after {GMAIL_CALL_TIMEOUT}s")
            return {"status": "error", "error_message": f"timeout after {GMAIL_CALL_TIMEOUT}s (email not sent)"}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
        except Exception as error:
            logger.error(f"send_email failed: {error}")
            return {"status": "error", "error_message": str(error)}

    async def open_email(self, email_id: str) -> str:
        """Opens email in browser given ID."""
        try:
            url = f"https://mail.google.com/#all/{email_id}"
            webbrowser.open(url, new=0, autoraise=True)
            return "Email opened in browser successfully."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"

    async def get_unread_emails(self) -> list[dict[str, str]]| str:
        """
        Retrieves unread messages from mailbox.
        Returns list of messsage IDs in key 'id'."""
        try:
            user_id = 'me'
            query = 'in:inbox is:unread category:primary'

            response = self.service.users().messages().list(userId=user_id,
                                                        q=query).execute()
            messages = []
            if 'messages' in response:
                messages.extend(response['messages'])

            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = self.service.users().messages().list(userId=user_id, q=query,
                                                    pageToken=page_token).execute()
                messages.extend(response['messages'])
            return messages

        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"

    async def read_email(self, email_id: str) -> dict[str, str]| str:
        """Retrieves email contents including to, from, subject, and contents."""
        try:
            msg = self.service.users().messages().get(userId="me", id=email_id, format='raw').execute()
            email_metadata = {}

            # Decode the base64URL encoded raw content
            raw_data = msg['raw']
            decoded_data = urlsafe_b64decode(raw_data)

            # Parse the RFC 2822 email
            mime_message = message_from_bytes(decoded_data)

            # Extract the email body
            body = None
            if mime_message.is_multipart():
                for part in mime_message.walk():
                    # Extract the text/plain part
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                # For non-multipart messages
                body = mime_message.get_payload(decode=True).decode()
            email_metadata['content'] = body
            
            # Extract metadata
            email_metadata['subject'] = decode_mime_header(mime_message.get('subject', ''))
            email_metadata['from'] = mime_message.get('from','')
            email_metadata['to'] = mime_message.get('to','')
            email_metadata['date'] = mime_message.get('date','')
            
            logger.info(f"Email read: {email_id}")
            
            # We want to mark email as read once we read it
            await self.mark_email_as_read(email_id)

            return email_metadata
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
        
    async def trash_email(self, email_id: str) -> str:
        """Moves email to trash given ID."""
        try:
            self.service.users().messages().trash(userId="me", id=email_id).execute()
            logger.info(f"Email moved to trash: {email_id}")
            return "Email moved to trash successfully."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
        
    async def mark_email_as_read(self, email_id: str) -> str:
        """Marks email as read given ID."""
        try:
            self.service.users().messages().modify(userId="me", id=email_id, body={'removeLabelIds': ['UNREAD']}).execute()
            logger.info(f"Email marked as read: {email_id}")
            return "Email marked as read."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
  
async def main(creds_file_path: str,
               token_path: str):

    # Must run before stdio_server() wraps sys.stdin/stdout (fixes cp1250 mojibake).
    _force_utf8_stdio()

    gmail_service = GmailService(creds_file_path, token_path)
    server = Server("gmail")

    @server.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return list(PROMPTS.values())

    @server.get_prompt()
    async def get_prompt(
        name: str, arguments: dict[str, str] | None = None
    ) -> types.GetPromptResult:
        if name not in PROMPTS:
            raise ValueError(f"Prompt not found: {name}")

        if name == "manage-email":
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=EMAIL_ADMIN_PROMPTS,
                        )
                    )
                ]
            )

        if name == "draft-email":
            content = arguments.get("content", "")
            recipient = arguments.get("recipient", "")
            recipient_email = arguments.get("recipient_email", "")
            
            # First message asks the LLM to create the draft
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""Please draft an email about {content} for {recipient} ({recipient_email}).
                            Include a subject line starting with 'Subject:' on the first line.
                            Do not send the email yet, just draft it and ask the user for their thoughts."""
                        )
                    )
                ]
            )
        
        elif name == "edit-draft":
            changes = arguments.get("changes", "")
            current_draft = arguments.get("current_draft", "")
            
            # Edit existing draft based on requested changes
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""Please revise the current email draft:
                            {current_draft}
                            
                            Requested changes:
                            {changes}
                            
                            Please provide the updated draft."""
                        )
                    )
                ]
            )

        raise ValueError("Prompt implementation not found")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="send-email",
                description="""Sends email to recipient.
                Supports both plain text and HTML bodies. Pass HTML in `message` and it
                is sent as a formatted HTML email (with an auto-generated plaintext
                fallback); set `html` explicitly to force the mode. UTF-8 (incl. Czech
                diacritics) is preserved.
                Do not use if user only asked to draft email.
                Drafts must be approved before sending.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "recipient_id": {
                            "type": "string",
                            "description": "Recipient email address",
                        },
                        "subject": {
                            "type": "string",
                            "description": "Email subject",
                        },
                        "message": {
                            "type": "string",
                            "description": "Email content. May be plain text or HTML.",
                        },
                        "html": {
                            "type": "boolean",
                            "description": "Optional. Send the body as HTML. If omitted, HTML is auto-detected from the message content.",
                        },
                    },
                    "required": ["recipient_id", "subject", "message"],
                },
            ),
            types.Tool(
                name="trash-email",
                description="""Moves email to trash. 
                Confirm before moving email to trash.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="get-unread-emails",
                description="Retrieve unread emails",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="read-email",
                description="Retrieves given email content",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="mark-email-as-read",
                description="Marks given email as read",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="open-email",
                description="Open email in browser",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="send-draft",
                description="Sends an existing Gmail draft by its draft ID. Use this to send drafts created by other Gmail MCP tools.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "draft_id": {
                            "type": "string",
                            "description": "Gmail draft ID to send",
                        },
                    },
                    "required": ["draft_id"],
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:

        if name == "send-email":
            recipient = arguments.get("recipient_id")
            if not recipient:
                raise ValueError("Missing recipient parameter")
            subject = arguments.get("subject")
            if not subject:
                raise ValueError("Missing subject parameter")
            message = arguments.get("message")
            if not message:
                raise ValueError("Missing message parameter")
            html = arguments.get("html")

            # Extract subject and message content. Only treat a leading "Subject:" line
            # as a header for plain-text bodies; HTML bodies are passed through verbatim.
            email_lines = message.split('\n')
            if email_lines and email_lines[0].startswith('Subject:'):
                subject = email_lines[0][8:].strip()
                message_content = '\n'.join(email_lines[1:]).strip()
            else:
                message_content = message

            send_response = await gmail_service.send_email(recipient, subject, message_content, html)
            
            if send_response["status"] == "success":
                response_text = f"Email sent successfully. Message ID: {send_response['message_id']}"
            else:
                response_text = f"Failed to send email: {send_response['error_message']}"
            return [types.TextContent(type="text", text=response_text)]

        if name == "get-unread-emails":
                
            unread_emails = await gmail_service.get_unread_emails()
            return [types.TextContent(type="text", text=str(unread_emails),artifact={"type": "json", "data": unread_emails} )]
        
        if name == "read-email":
            email_id = arguments.get("email_id")
            if not email_id:
                raise ValueError("Missing email ID parameter")
                
            retrieved_email = await gmail_service.read_email(email_id)
            return [types.TextContent(type="text", text=str(retrieved_email),artifact={"type": "dictionary", "data": retrieved_email} )]
        if name == "open-email":
            email_id = arguments.get("email_id")
            if not email_id:
                raise ValueError("Missing email ID parameter")
                
            msg = await gmail_service.open_email(email_id)
            return [types.TextContent(type="text", text=str(msg))]
        if name == "trash-email":
            email_id = arguments.get("email_id")
            if not email_id:
                raise ValueError("Missing email ID parameter")
                
            msg = await gmail_service.trash_email(email_id)
            return [types.TextContent(type="text", text=str(msg))]
        if name == "mark-email-as-read":
            email_id = arguments.get("email_id")
            if not email_id:
                raise ValueError("Missing email ID parameter")

            msg = await gmail_service.mark_email_as_read(email_id)
            return [types.TextContent(type="text", text=str(msg))]
        if name == "send-draft":
            draft_id = arguments.get("draft_id")
            if not draft_id:
                raise ValueError("Missing draft_id parameter")

            send_response = await gmail_service.send_draft(draft_id)

            if send_response["status"] == "success":
                response_text = f"Draft sent successfully. Message ID: {send_response['message_id']}"
            else:
                response_text = f"Failed to send draft: {send_response['error_message']}"
            return [types.TextContent(type="text", text=response_text)]
        else:
            logger.error(f"Unknown tool: {name}")
            raise ValueError(f"Unknown tool: {name}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="gmail",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Gmail API MCP Server')
    parser.add_argument('--creds-file-path',
                        required=True,
                       help='OAuth 2.0 credentials file path')
    parser.add_argument('--token-path',
                        required=True,
                       help='File location to store and retrieve access and refresh tokens for application')
    
    args = parser.parse_args()
    asyncio.run(main(args.creds_file_path, args.token_path))