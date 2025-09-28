"""POP3 Server implementation for email retrieval."""

from typing import Any, Dict, Optional

from pydantic import Field

from primaite import getLogger
from primaite.interface.request import RequestFormat, RequestResponse
from primaite.simulator.core import RequestManager, RequestType
from primaite.simulator.system.services.service import Service
from primaite.utils.validation.ip_protocol import PROTOCOL_LOOKUP
from primaite.utils.validation.port import PORT_LOOKUP

from primaite_mail.simulator.network.protocols.pop3 import POP3Command, POP3Packet, POP3Status
from primaite_mail.simulator.software.mailbox import MailboxManager

_LOGGER = getLogger(__name__)


class POP3Server(Service, discriminator="pop3-server"):
    """
    POP3 Server service for email retrieval.
    
    Implements RFC 1939 POP3 protocol for retrieving emails from mailboxes.
    """

    class ConfigSchema(Service.ConfigSchema):
        """ConfigSchema for POP3Server."""

        type: str = "pop3-server"
        require_auth: bool = True

    config: ConfigSchema = Field(default_factory=lambda: POP3Server.ConfigSchema())
    mailbox_manager: MailboxManager = Field(default_factory=MailboxManager)
    active_sessions: Dict[str, Dict] = Field(default_factory=dict)

    def __init__(self, **kwargs):
        kwargs["name"] = "pop3-server"
        kwargs["port"] = PORT_LOOKUP["POP3"]
        kwargs["protocol"] = PROTOCOL_LOOKUP["TCP"]
        super().__init__(**kwargs)
        self.start()

    def _init_request_manager(self) -> RequestManager:
        """Initialize the request manager with POP3-specific requests."""
        rm = super()._init_request_manager()
        
        def _authenticate_user_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Authenticate a user for POP3 access."""
            params = request[-1]
            username = params.get("username")
            password = params.get("password")
            
            if not username or not password:
                return RequestResponse(status="failure", data={"reason": "Username and password required"})
            
            # Simple authentication - check if mailbox exists
            mailbox = self.mailbox_manager.get_mailbox(username)
            if mailbox:
                return RequestResponse(status="success", data={
                    "username": username,
                    "authenticated": True,
                    "message_count": len(mailbox.get_messages())
                })
            else:
                return RequestResponse(status="failure", data={"reason": "Authentication failed"})
        
        def _get_message_list_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get list of messages for a user."""
            params = request[-1]
            username = params.get("username")
            
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            mailbox = self.mailbox_manager.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            messages = mailbox.get_messages()
            message_list = []
            for i, msg in enumerate(messages, 1):
                msg_size = len(msg.body) + len(msg.subject) + len(msg.sender) + sum(len(r) for r in msg.recipients)
                message_list.append({
                    "number": i,
                    "size": msg_size,
                    "subject": msg.subject,
                    "sender": msg.sender
                })
            
            return RequestResponse(status="success", data={
                "username": username,
                "message_count": len(messages),
                "total_size": sum(msg["size"] for msg in message_list),
                "messages": message_list
            })
        
        def _retrieve_message_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Retrieve a specific message."""
            params = request[-1]
            username = params.get("username")
            message_number = params.get("message_number")
            
            if not username or message_number is None:
                return RequestResponse(status="failure", data={"reason": "Username and message number required"})
            
            try:
                message_number = int(message_number)
            except ValueError:
                return RequestResponse(status="failure", data={"reason": "Invalid message number"})
            
            mailbox = self.mailbox_manager.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            messages = mailbox.get_messages()
            if message_number < 1 or message_number > len(messages):
                return RequestResponse(status="failure", data={"reason": "Message number out of range"})
            
            msg = messages[message_number - 1]
            return RequestResponse(status="success", data={
                "message_number": message_number,
                "message_id": msg.message_id,
                "sender": msg.sender,
                "recipients": msg.recipients,
                "subject": msg.subject,
                "body": msg.body,
                "timestamp": msg.timestamp
            })
        
        def _delete_message_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Mark a message for deletion."""
            params = request[-1]
            username = params.get("username")
            message_number = params.get("message_number")
            
            if not username or message_number is None:
                return RequestResponse(status="failure", data={"reason": "Username and message number required"})
            
            try:
                message_number = int(message_number)
            except ValueError:
                return RequestResponse(status="failure", data={"reason": "Invalid message number"})
            
            mailbox = self.mailbox_manager.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            messages = mailbox.get_messages()
            if message_number < 1 or message_number > len(messages):
                return RequestResponse(status="failure", data={"reason": "Message number out of range"})
            
            msg = messages[message_number - 1]
            success = mailbox.delete_message(msg.message_id)
            if success:
                return RequestResponse(status="success", data={"message_number": message_number})
            else:
                return RequestResponse(status="failure", data={"reason": "Failed to delete message"})

        rm.add_request("authenticate_user", RequestType(func=_authenticate_user_request))
        rm.add_request("get_message_list", RequestType(func=_get_message_list_request))
        rm.add_request("retrieve_message", RequestType(func=_retrieve_message_request))
        rm.add_request("delete_message", RequestType(func=_delete_message_request))
        return rm

    def _process_pop3_command(self, packet: POP3Packet, session_id: Optional[str] = None) -> POP3Packet:
        """Process POP3 commands and generate appropriate responses."""
        if not self._can_perform_action():
            return POP3Packet(
                status=POP3Status.ERR,
                message="Service temporarily unavailable"
            )

        self.sys_log.info(f"{self.name}: Received POP3 {packet.command.name if packet.command else 'UNKNOWN'}")

        # Initialize session if needed
        if session_id and session_id not in self.active_sessions:
            self.active_sessions[session_id] = {
                "state": "authorization",
                "username": None,
                "authenticated": False,
                "mailbox": None
            }

        session = self.active_sessions.get(session_id, {})

        if packet.command == POP3Command.USER:
            return self._handle_user(packet, session)
        elif packet.command == POP3Command.PASS:
            return self._handle_pass(packet, session)
        elif packet.command == POP3Command.STAT:
            return self._handle_stat(packet, session)
        elif packet.command == POP3Command.LIST:
            return self._handle_list(packet, session)
        elif packet.command == POP3Command.RETR:
            return self._handle_retr(packet, session)
        elif packet.command == POP3Command.DELE:
            return self._handle_dele(packet, session)
        elif packet.command == POP3Command.QUIT:
            return self._handle_quit(packet, session_id)
        elif packet.command == POP3Command.NOOP:
            return POP3Packet(status=POP3Status.OK, message="OK")
        else:
            return POP3Packet(status=POP3Status.ERR, message="Command not implemented")

    def _handle_user(self, packet: POP3Packet, session: Dict) -> POP3Packet:
        """Handle USER command."""
        if session.get("state") != "authorization":
            return POP3Packet(status=POP3Status.ERR, message="Already authenticated")
        
        username = packet.arguments
        if username:
            session["username"] = username
            return POP3Packet(status=POP3Status.OK, message=f"User {username} OK")
        
        return POP3Packet(status=POP3Status.ERR, message="Username required")

    def _handle_pass(self, packet: POP3Packet, session: Dict) -> POP3Packet:
        """Handle PASS command."""
        if session.get("state") != "authorization":
            return POP3Packet(status=POP3Status.ERR, message="Send USER first")
        
        username = session.get("username")
        password = packet.arguments
        
        # Simple authentication - in real scenario would check against user database
        if username and password:
            mailbox = self.mailbox_manager.get_mailbox(username)
            if mailbox:
                session["authenticated"] = True
                session["mailbox"] = mailbox
                session["state"] = "transaction"
                return POP3Packet(status=POP3Status.OK, message="Authentication successful")
        
        return POP3Packet(status=POP3Status.ERR, message="Authentication failed")

    def _handle_stat(self, packet: POP3Packet, session: Dict) -> POP3Packet:
        """Handle STAT command."""
        if not session.get("authenticated"):
            return POP3Packet(status=POP3Status.ERR, message="Not authenticated")
        
        mailbox = session.get("mailbox")
        if mailbox:
            message_count = len(mailbox.get_messages())
            # Simple size calculation (in real scenario would calculate actual size)
            total_size = message_count * 1024  # Assume 1KB per message
            return POP3Packet(status=POP3Status.OK, message=f"{message_count} {total_size}")
        
        return POP3Packet(status=POP3Status.ERR, message="Mailbox unavailable")

    def _handle_list(self, packet: POP3Packet, session: Dict) -> POP3Packet:
        """Handle LIST command."""
        if not session.get("authenticated"):
            return POP3Packet(status=POP3Status.ERR, message="Not authenticated")
        
        mailbox = session.get("mailbox")
        if mailbox:
            messages = mailbox.get_messages()
            if packet.arguments:
                # List specific message
                try:
                    msg_num = int(packet.arguments) - 1
                    if 0 <= msg_num < len(messages):
                        return POP3Packet(status=POP3Status.OK, message=f"{msg_num + 1} 1024")
                    else:
                        return POP3Packet(status=POP3Status.ERR, message="No such message")
                except ValueError:
                    return POP3Packet(status=POP3Status.ERR, message="Invalid message number")
            else:
                # List all messages
                message_list = []
                for i, msg in enumerate(messages):
                    message_list.append(f"{i + 1} 1024")  # Message number and size
                
                response_text = f"{len(messages)} messages\n" + "\n".join(message_list)
                return POP3Packet(status=POP3Status.OK, message=response_text)
        
        return POP3Packet(status=POP3Status.ERR, message="Mailbox unavailable")

    def _handle_retr(self, packet: POP3Packet, session: Dict) -> POP3Packet:
        """Handle RETR command."""
        if not session.get("authenticated"):
            return POP3Packet(status=POP3Status.ERR, message="Not authenticated")
        
        mailbox = session.get("mailbox")
        if mailbox and packet.arguments:
            try:
                msg_num = int(packet.arguments) - 1
                messages = mailbox.get_messages()
                if 0 <= msg_num < len(messages):
                    email = messages[msg_num]
                    return POP3Packet(
                        status=POP3Status.OK,
                        message=f"Message {msg_num + 1}",
                        email_data=email
                    )
                else:
                    return POP3Packet(status=POP3Status.ERR, message="No such message")
            except ValueError:
                return POP3Packet(status=POP3Status.ERR, message="Invalid message number")
        
        return POP3Packet(status=POP3Status.ERR, message="Message number required")

    def _handle_dele(self, packet: POP3Packet, session: Dict) -> POP3Packet:
        """Handle DELE command."""
        if not session.get("authenticated"):
            return POP3Packet(status=POP3Status.ERR, message="Not authenticated")
        
        mailbox = session.get("mailbox")
        if mailbox and packet.arguments:
            try:
                msg_num = int(packet.arguments) - 1
                messages = mailbox.get_messages()
                if 0 <= msg_num < len(messages):
                    email = messages[msg_num]
                    if mailbox.delete_message(email.message_id):
                        return POP3Packet(status=POP3Status.OK, message=f"Message {msg_num + 1} deleted")
                    else:
                        return POP3Packet(status=POP3Status.ERR, message="Delete failed")
                else:
                    return POP3Packet(status=POP3Status.ERR, message="No such message")
            except ValueError:
                return POP3Packet(status=POP3Status.ERR, message="Invalid message number")
        
        return POP3Packet(status=POP3Status.ERR, message="Message number required")

    def _handle_quit(self, packet: POP3Packet, session_id: Optional[str]) -> POP3Packet:
        """Handle QUIT command."""
        if session_id and session_id in self.active_sessions:
            del self.active_sessions[session_id]
        return POP3Packet(status=POP3Status.OK, message="POP3 server signing off")

    def receive(self, payload: Any, session_id: Optional[str] = None, **kwargs) -> bool:
        """Receive and process POP3 packets."""
        if not isinstance(payload, POP3Packet):
            self.sys_log.warning(f"{self.name}: Payload is not a POP3 packet")
            return False

        if not super().receive(payload=payload, session_id=session_id, **kwargs):
            return False

        response = self._process_pop3_command(payload, session_id)
        
        if response:
            return self.send(payload=response, session_id=session_id)
        
        return True

    def show(self, markdown: bool = False):
        """Display POP3 server status and session information in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Server status table
        status_table = PrettyTable(["Property", "Value"])
        if markdown:
            status_table.set_style(MARKDOWN)
        status_table.align = "l"
        status_table.title = f"POP3 Server Status ({self.sys_log.hostname})"
        
        status_table.add_row(["Service Name", self.name])
        status_table.add_row(["Operating State", self.operating_state.name])
        status_table.add_row(["Health State", self.health_state_actual.name])
        status_table.add_row(["Port", self.port])
        status_table.add_row(["Protocol", self.protocol])
        status_table.add_row(["Active Sessions", len(self.active_sessions)])
        status_table.add_row(["Total Mailboxes", len(self.mailbox_manager.mailboxes)])
        status_table.add_row(["Authentication Required", self.config.require_auth])
        
        print(status_table)
        
        # Active sessions table
        if self.active_sessions:
            session_table = PrettyTable(["Session ID", "State", "Username", "Authenticated", "Mailbox"])
            if markdown:
                session_table.set_style(MARKDOWN)
            session_table.align = "l"
            session_table.title = f"Active POP3 Sessions ({self.sys_log.hostname})"
            
            for session_id, session_data in self.active_sessions.items():
                mailbox_name = session_data.get("mailbox", {}).get("username", "none") if session_data.get("mailbox") else "none"
                session_table.add_row([
                    session_id[:8] + "..." if len(session_id) > 8 else session_id,
                    session_data.get("state", "unknown"),
                    session_data.get("username", "none"),
                    "Yes" if session_data.get("authenticated") else "No",
                    mailbox_name
                ])
            
            print(session_table)

    def show_mailbox(self, username: str = None, markdown: bool = False):
        """Display mailbox contents for a specific user or all users in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        if username:
            # Show specific user's mailbox
            mailbox = self.mailbox_manager.get_mailbox(username)
            if not mailbox:
                print(f"Mailbox for user '{username}' not found")
                return
            
            messages = mailbox.get_messages()
            if not messages:
                print(f"{username}'s mailbox is empty")
                return
            
            msg_table = PrettyTable(["#", "From", "To", "Subject", "Size", "Status"])
            if markdown:
                msg_table.set_style(MARKDOWN)
            msg_table.align = "l"
            msg_table.title = f"POP3 View: {username}'s Mailbox ({len(messages)} messages)"
            
            for i, msg in enumerate(messages, 1):
                # Calculate approximate message size
                msg_size = len(msg.body) + len(msg.subject) + len(msg.sender) + sum(len(r) for r in msg.recipients)
                msg_table.add_row([
                    i,
                    msg.sender[:20] + "..." if len(msg.sender) > 20 else msg.sender,
                    ", ".join(msg.recipients)[:20] + "..." if len(", ".join(msg.recipients)) > 20 else ", ".join(msg.recipients),
                    msg.subject[:30] + "..." if len(msg.subject) > 30 else msg.subject,
                    f"{msg_size} bytes",
                    "Unread"  # In a real implementation, this would track read status
                ])
            
            print(msg_table)
        else:
            # Show all mailboxes
            if not self.mailbox_manager.mailboxes:
                print("No mailboxes found")
                return
            
            for username, mailbox in self.mailbox_manager.mailboxes.items():
                messages = mailbox.get_messages()
                if messages:
                    print(f"\n{'='*60}")
                    self.show_mailbox(username, markdown)

    def show_message(self, username: str, message_number: int, markdown: bool = False):
        """Display detailed content of a specific message in POP3 format."""
        from prettytable import PrettyTable, MARKDOWN
        
        mailbox = self.mailbox_manager.get_mailbox(username)
        if not mailbox:
            print(f"Mailbox for user '{username}' not found")
            return
        
        messages = mailbox.get_messages()
        if message_number < 1 or message_number > len(messages):
            print(f"Message {message_number} not found. Valid range: 1-{len(messages)}")
            return
        
        msg = messages[message_number - 1]
        
        # POP3-style message display
        details_table = PrettyTable(["Field", "Value"])
        if markdown:
            details_table.set_style(MARKDOWN)
        details_table.align = "l"
        details_table.title = f"POP3 RETR: Message {message_number} ({username})"
        
        msg_size = len(msg.body) + len(msg.subject) + len(msg.sender) + sum(len(r) for r in msg.recipients)
        details_table.add_row(["Message Number", message_number])
        details_table.add_row(["Size", f"{msg_size} bytes"])
        details_table.add_row(["From", msg.sender])
        details_table.add_row(["To", ", ".join(msg.recipients)])
        details_table.add_row(["Subject", msg.subject])
        details_table.add_row(["Status", "Retrieved via POP3"])
        
        print(details_table)
        
        # Message content
        content_table = PrettyTable(["Message Content"])
        if markdown:
            content_table.set_style(MARKDOWN)
        content_table.align = "l"
        content_table.title = f"Message {message_number} Body"
        
        body_lines = msg.body.split('\n')
        for line in body_lines:
            if len(line) > 80:
                while line:
                    content_table.add_row([line[:80]])
                    line = line[80:]
            else:
                content_table.add_row([line])
        
        print(content_table)

    def describe_state(self) -> Dict:
        """Describe the current state of the POP3 server."""
        state = super().describe_state()
        state["active_sessions"] = len(self.active_sessions)
        state["total_mailboxes"] = len(self.mailbox_manager.mailboxes)
        return state