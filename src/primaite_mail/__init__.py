"""All simulation layer and game layer additions that make up primaite-mail for email simulation."""

from primaite_mail.game.agents import GreenMailAgent
from primaite_mail.game.actions.email_actions import EmailSendAction, EmailRetrieveAction, EmailConfigureAction
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.pop3_server import POP3Server
from primaite_mail.simulator.software.email_client import EmailClient

__version__ = "1.0.0"
__all__ = (
    "GreenMailAgent", 
    "EmailSendAction", "EmailRetrieveAction", "EmailConfigureAction",
    "SMTPServer", "POP3Server", "EmailClient"
)