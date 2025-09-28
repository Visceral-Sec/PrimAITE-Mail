"""Email-specific actions for agents."""

from primaite_mail.game.actions.email_actions import (
    EmailSendAction, 
    EmailRetrieveAction, 
    EmailConfigureAction,
    EmailSendWithAttachmentsAction,
    EmailExtractAttachmentsAction,
    EmailScanAttachmentsAction,
    EmailQuarantineMessageAction
)

__all__ = (
    "EmailSendAction", 
    "EmailRetrieveAction", 
    "EmailConfigureAction",
    "EmailSendWithAttachmentsAction",
    "EmailExtractAttachmentsAction",
    "EmailScanAttachmentsAction",
    "EmailQuarantineMessageAction"
)