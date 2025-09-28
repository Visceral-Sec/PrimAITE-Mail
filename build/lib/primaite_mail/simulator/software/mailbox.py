"""Mailbox management for email storage and organization."""

from typing import Dict, List, Optional
from datetime import datetime
import uuid

from pydantic import BaseModel, Field

from primaite.interface.request import RequestFormat, RequestResponse
from primaite.simulator.core import RequestManager, RequestType, SimComponent
from primaite_mail.simulator.network.protocols.smtp import EmailMessage
from primaite_mail.simulator.network.protocols.imap import IMAPFolder


class Mailbox(BaseModel):
    """Represents a user's mailbox with folders and messages."""
    
    username: str
    folders: Dict[str, IMAPFolder] = Field(default_factory=lambda: {
        "INBOX": IMAPFolder(name="INBOX"),
        "Sent": IMAPFolder(name="Sent"),
        "Drafts": IMAPFolder(name="Drafts"),
        "Trash": IMAPFolder(name="Trash")
    })
    total_messages: int = 0
    
    # Attachment tracking fields
    total_attachments: int = 0
    total_attachment_size: int = 0  # Total size of all attachments in bytes
    attachment_cleanup_policy: Dict[str, int] = Field(default_factory=lambda: {
        "max_age_days": 30,  # Delete attachments older than 30 days
        "max_total_size": 100 * 1024 * 1024,  # 100MB total attachment storage limit
        "cleanup_enabled": True
    })
    
    def add_message(self, message: EmailMessage, folder_name: str = "INBOX") -> bool:
        """Add a message to the specified folder with attachment handling."""
        if folder_name not in self.folders:
            return False
            
        # Set message ID and timestamp if not present
        if not message.message_id:
            message.message_id = str(uuid.uuid4())
        if not message.timestamp:
            message.timestamp = datetime.now().isoformat()
        
        # Update attachment statistics
        if message.has_attachments:
            self.total_attachments += len(message.attachments)
            attachment_size = sum(attachment.file_size for attachment in message.attachments)
            self.total_attachment_size += attachment_size
            
            # Check if cleanup is needed based on policy
            if self.attachment_cleanup_policy.get("cleanup_enabled", True):
                self._check_attachment_cleanup()
            
        self.folders[folder_name].messages.append(message)
        self.folders[folder_name].exists += 1
        self.folders[folder_name].recent += 1
        self.total_messages += 1
        return True
    
    def get_messages(self, folder_name: str = "INBOX") -> List[EmailMessage]:
        """Get all messages from the specified folder."""
        if folder_name not in self.folders:
            return []
        return self.folders[folder_name].messages
    
    def delete_message(self, message_id: str, folder_name: str = "INBOX") -> bool:
        """Delete a message from the specified folder with attachment cleanup."""
        if folder_name not in self.folders:
            return False
            
        folder = self.folders[folder_name]
        for i, message in enumerate(folder.messages):
            if message.message_id == message_id:
                # Update attachment statistics before deletion
                if message.has_attachments:
                    self.total_attachments -= len(message.attachments)
                    attachment_size = sum(attachment.file_size for attachment in message.attachments)
                    self.total_attachment_size -= attachment_size
                
                folder.messages.pop(i)
                folder.exists -= 1
                self.total_messages -= 1
                return True
        return False
    
    def create_folder(self, folder_name: str) -> bool:
        """Create a new folder."""
        if folder_name in self.folders:
            return False
        self.folders[folder_name] = IMAPFolder(name=folder_name)
        return True
    
    def delete_folder(self, folder_name: str) -> bool:
        """Delete a folder (cannot delete default folders)."""
        if folder_name in ["INBOX", "Sent", "Drafts", "Trash"]:
            return False
        if folder_name not in self.folders:
            return False
        
        # Update attachment statistics for messages in the deleted folder
        folder = self.folders[folder_name]
        for message in folder.messages:
            if message.has_attachments:
                self.total_attachments -= len(message.attachments)
                attachment_size = sum(attachment.file_size for attachment in message.attachments)
                self.total_attachment_size -= attachment_size
            self.total_messages -= 1
        
        del self.folders[folder_name]
        return True
    
    def get_attachment_statistics(self) -> Dict[str, int]:
        """Get attachment statistics for this mailbox."""
        return {
            "total_attachments": self.total_attachments,
            "total_attachment_size": self.total_attachment_size,
            "messages_with_attachments": sum(
                1 for folder in self.folders.values() 
                for message in folder.messages 
                if message.has_attachments
            ),
            "average_attachment_size": (
                self.total_attachment_size // self.total_attachments 
                if self.total_attachments > 0 else 0
            )
        }
    
    def get_messages_with_attachments(self, folder_name: str = None) -> List[EmailMessage]:
        """Get all messages that have attachments, optionally filtered by folder."""
        messages_with_attachments = []
        
        folders_to_check = [folder_name] if folder_name else self.folders.keys()
        
        for fname in folders_to_check:
            if fname in self.folders:
                for message in self.folders[fname].messages:
                    if message.has_attachments:
                        messages_with_attachments.append(message)
        
        return messages_with_attachments
    
    def _check_attachment_cleanup(self) -> None:
        """Check if attachment cleanup is needed based on policy."""
        policy = self.attachment_cleanup_policy
        
        # Check total size limit
        max_size = policy.get("max_total_size", 100 * 1024 * 1024)
        if self.total_attachment_size > max_size:
            self._cleanup_old_attachments()
        
        # Check age-based cleanup
        max_age_days = policy.get("max_age_days", 30)
        if max_age_days > 0:
            self._cleanup_attachments_by_age(max_age_days)
    
    def _cleanup_old_attachments(self) -> int:
        """Clean up old attachments to free space. Returns number of messages cleaned."""
        from datetime import datetime, timedelta
        
        cleaned_count = 0
        messages_to_clean = []
        
        # Collect messages with attachments, sorted by timestamp (oldest first)
        for folder in self.folders.values():
            for message in folder.messages:
                if message.has_attachments and message.timestamp:
                    try:
                        msg_time = datetime.fromisoformat(message.timestamp.replace('Z', '+00:00'))
                        messages_to_clean.append((message, msg_time))
                    except ValueError:
                        # If timestamp parsing fails, consider it old
                        messages_to_clean.append((message, datetime.min))
        
        # Sort by timestamp (oldest first)
        messages_to_clean.sort(key=lambda x: x[1])
        
        # Remove attachments from oldest messages until under size limit
        max_size = self.attachment_cleanup_policy.get("max_total_size", 100 * 1024 * 1024)
        
        for message, _ in messages_to_clean:
            if self.total_attachment_size <= max_size:
                break
            
            # Remove attachments from this message
            attachment_size = sum(attachment.file_size for attachment in message.attachments)
            self.total_attachments -= len(message.attachments)
            self.total_attachment_size -= attachment_size
            message.attachments.clear()
            cleaned_count += 1
        
        return cleaned_count
    
    def _cleanup_attachments_by_age(self, max_age_days: int) -> int:
        """Clean up attachments older than specified days. Returns number of messages cleaned."""
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        cleaned_count = 0
        
        for folder in self.folders.values():
            for message in folder.messages:
                if message.has_attachments and message.timestamp:
                    try:
                        msg_time = datetime.fromisoformat(message.timestamp.replace('Z', '+00:00'))
                        if msg_time < cutoff_date:
                            # Remove attachments from this old message
                            attachment_size = sum(attachment.file_size for attachment in message.attachments)
                            self.total_attachments -= len(message.attachments)
                            self.total_attachment_size -= attachment_size
                            message.attachments.clear()
                            cleaned_count += 1
                    except ValueError:
                        # If timestamp parsing fails, skip this message
                        continue
        
        return cleaned_count
    
    def update_attachment_cleanup_policy(self, policy_updates: Dict[str, int]) -> bool:
        """Update the attachment cleanup policy."""
        try:
            self.attachment_cleanup_policy.update(policy_updates)
            return True
        except Exception:
            return False


class MailboxManager(SimComponent):
    """Manages multiple user mailboxes."""
    
    mailboxes: Dict[str, Mailbox] = Field(default_factory=dict)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _init_request_manager(self) -> RequestManager:
        """Initialize the request manager with mailbox management requests."""
        rm = RequestManager()
        
        def _create_mailbox_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Create a new mailbox."""
            username = request[-1].get("username")
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            success = self.create_mailbox(username)
            if success:
                return RequestResponse(status="success", data={"username": username})
            else:
                return RequestResponse(status="failure", data={"reason": f"Failed to create mailbox for {username}"})
        
        def _delete_mailbox_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Delete a mailbox."""
            username = request[-1].get("username")
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            success = self.delete_mailbox(username)
            if success:
                return RequestResponse(status="success", data={"username": username})
            else:
                return RequestResponse(status="failure", data={"reason": f"Failed to delete mailbox for {username}"})
        
        def _list_mailboxes_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """List all mailboxes."""
            mailbox_info = {}
            for username, mailbox in self.mailboxes.items():
                mailbox_info[username] = {
                    "total_messages": len(mailbox.get_messages()),
                    "folders": list(mailbox.folders.keys()),
                    "folder_counts": {
                        folder_name: len(folder.messages) 
                        for folder_name, folder in mailbox.folders.items()
                    }
                }
            
            return RequestResponse(status="success", data={
                "total_mailboxes": len(self.mailboxes),
                "mailboxes": mailbox_info
            })
        
        def _get_mailbox_info_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get detailed information about a specific mailbox."""
            username = request[-1].get("username")
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            mailbox = self.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            folder_info = {}
            for folder_name, folder in mailbox.folders.items():
                folder_info[folder_name] = {
                    "message_count": len(folder.messages),
                    "exists": folder.exists,
                    "recent": folder.recent,
                    "unseen": folder.unseen
                }
            
            return RequestResponse(status="success", data={
                "username": username,
                "total_messages": mailbox.total_messages,
                "folders": folder_info
            })
        
        def _add_message_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Add a message to a mailbox."""
            params = request[-1]
            username = params.get("username")
            folder = params.get("folder", "INBOX")
            sender = params.get("sender")
            recipients = params.get("recipients", [])
            subject = params.get("subject", "")
            body = params.get("body", "")
            
            if not username or not sender:
                return RequestResponse(status="failure", data={"reason": "Username and sender required"})
            
            if isinstance(recipients, str):
                recipients = [recipients]
            
            mailbox = self.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            # Create email message
            email = EmailMessage(
                sender=sender,
                recipients=recipients,
                subject=subject,
                body=body
            )
            
            success = mailbox.add_message(email, folder)
            if success:
                return RequestResponse(status="success", data={
                    "username": username,
                    "folder": folder,
                    "message_id": email.message_id
                })
            else:
                return RequestResponse(status="failure", data={"reason": "Failed to add message to mailbox"})
        
        def _get_mailbox_messages_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get messages from a mailbox with attachment information."""
            params = request[-1]
            username = params.get("username")
            folder = params.get("folder", "INBOX")
            include_attachments = params.get("include_attachments", True)
            
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            mailbox = self.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            messages = mailbox.get_messages(folder)
            message_data = []
            
            for msg in messages:
                msg_info = {
                    "message_id": msg.message_id,
                    "sender": msg.sender,
                    "recipients": msg.recipients,
                    "subject": msg.subject,
                    "timestamp": msg.timestamp,
                    "has_attachments": msg.has_attachments,
                    "attachment_count": len(msg.attachments),
                    "total_size": msg.calculate_total_size()
                }
                
                if include_attachments and msg.has_attachments:
                    msg_info["attachments"] = [
                        {
                            "filename": att.filename,
                            "content_type": att.content_type,
                            "file_size": att.file_size,
                            "health_status": att.health_status
                        }
                        for att in msg.attachments
                    ]
                
                message_data.append(msg_info)
            
            return RequestResponse(status="success", data={
                "username": username,
                "folder": folder,
                "message_count": len(messages),
                "messages": message_data
            })
        
        def _get_message_attachments_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get detailed attachment metadata for a specific message."""
            params = request[-1]
            username = params.get("username")
            message_id = params.get("message_id")
            folder = params.get("folder", "INBOX")
            
            if not username or not message_id:
                return RequestResponse(status="failure", data={"reason": "Username and message_id required"})
            
            mailbox = self.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            # Find the message
            target_message = None
            if folder in mailbox.folders:
                for msg in mailbox.folders[folder].messages:
                    if msg.message_id == message_id:
                        target_message = msg
                        break
            
            if not target_message:
                return RequestResponse(status="failure", data={"reason": f"Message {message_id} not found in folder {folder}"})
            
            if not target_message.has_attachments:
                return RequestResponse(status="success", data={
                    "username": username,
                    "message_id": message_id,
                    "folder": folder,
                    "has_attachments": False,
                    "attachments": []
                })
            
            attachment_details = []
            for att in target_message.attachments:
                attachment_details.append({
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "file_size": att.file_size,
                    "file_uuid": att.file_uuid,
                    "health_status": att.health_status,
                    "encoded_size": len(att.file_data)
                })
            
            return RequestResponse(status="success", data={
                "username": username,
                "message_id": message_id,
                "folder": folder,
                "has_attachments": True,
                "attachment_count": len(target_message.attachments),
                "total_attachment_size": sum(att.file_size for att in target_message.attachments),
                "attachments": attachment_details
            })
        
        def _mailbox_stats_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get mailbox statistics including attachment storage metrics."""
            params = request[-1]
            username = params.get("username")
            
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            mailbox = self.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            # Get attachment statistics
            attachment_stats = mailbox.get_attachment_statistics()
            
            # Get folder statistics
            folder_stats = {}
            for folder_name, folder in mailbox.folders.items():
                messages_with_attachments = sum(1 for msg in folder.messages if msg.has_attachments)
                total_folder_attachment_size = sum(
                    sum(att.file_size for att in msg.attachments)
                    for msg in folder.messages if msg.has_attachments
                )
                
                folder_stats[folder_name] = {
                    "total_messages": len(folder.messages),
                    "messages_with_attachments": messages_with_attachments,
                    "total_attachment_size": total_folder_attachment_size,
                    "exists": folder.exists,
                    "recent": folder.recent,
                    "unseen": folder.unseen
                }
            
            return RequestResponse(status="success", data={
                "username": username,
                "total_messages": mailbox.total_messages,
                "attachment_statistics": attachment_stats,
                "folder_statistics": folder_stats,
                "cleanup_policy": mailbox.attachment_cleanup_policy,
                "storage_usage": {
                    "total_size_bytes": mailbox.total_attachment_size,
                    "total_size_mb": round(mailbox.total_attachment_size / (1024 * 1024), 2),
                    "max_allowed_mb": round(mailbox.attachment_cleanup_policy.get("max_total_size", 0) / (1024 * 1024), 2)
                }
            })
        
        def _delete_message_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Delete a message from a mailbox with attachment cleanup."""
            params = request[-1]
            username = params.get("username")
            message_id = params.get("message_id")
            folder = params.get("folder", "INBOX")
            
            if not username or not message_id:
                return RequestResponse(status="failure", data={"reason": "Username and message_id required"})
            
            mailbox = self.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            # Get message info before deletion for response
            message_to_delete = None
            if folder in mailbox.folders:
                for msg in mailbox.folders[folder].messages:
                    if msg.message_id == message_id:
                        message_to_delete = msg
                        break
            
            success = mailbox.delete_message(message_id, folder)
            if success:
                response_data = {
                    "username": username,
                    "folder": folder,
                    "message_id": message_id,
                    "had_attachments": message_to_delete.has_attachments if message_to_delete else False,
                    "attachments_cleaned": len(message_to_delete.attachments) if message_to_delete and message_to_delete.has_attachments else 0
                }
                return RequestResponse(status="success", data=response_data)
            else:
                return RequestResponse(status="failure", data={"reason": "Failed to delete message from mailbox"})

        rm.add_request("create_mailbox", RequestType(func=_create_mailbox_request))
        rm.add_request("delete_mailbox", RequestType(func=_delete_mailbox_request))
        rm.add_request("list_mailboxes", RequestType(func=_list_mailboxes_request))
        rm.add_request("get_mailbox_info", RequestType(func=_get_mailbox_info_request))
        rm.add_request("add_message", RequestType(func=_add_message_request))
        rm.add_request("delete_message", RequestType(func=_delete_message_request))
        rm.add_request("get_mailbox_messages", RequestType(func=_get_mailbox_messages_request))
        rm.add_request("get_message_attachments", RequestType(func=_get_message_attachments_request))
        rm.add_request("mailbox_stats", RequestType(func=_mailbox_stats_request))
        return rm
    
    def create_mailbox(self, username: str) -> bool:
        """Create a new mailbox for a user."""
        if username in self.mailboxes:
            return False
        self.mailboxes[username] = Mailbox(username=username)
        return True
    
    def get_mailbox(self, username: str) -> Optional[Mailbox]:
        """Get a user's mailbox."""
        return self.mailboxes.get(username)
    
    def delete_mailbox(self, username: str) -> bool:
        """Delete a user's mailbox."""
        if username not in self.mailboxes:
            return False
        del self.mailboxes[username]
        return True
    
    def show(self, markdown: bool = False, show_messages: bool = False):
        """Display mailbox manager status in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Mailbox summary table with attachment information
        summary_table = PrettyTable(["Username", "Messages", "INBOX", "Sent", "Drafts", "Trash", "Attachments", "Att. Size (MB)"])
        if markdown:
            summary_table.set_style(MARKDOWN)
        summary_table.align = "l"
        summary_table.title = "Mailbox Manager Summary"
        
        for username, mailbox in self.mailboxes.items():
            inbox_count = len(mailbox.folders.get("INBOX").messages) if "INBOX" in mailbox.folders else 0
            sent_count = len(mailbox.folders.get("Sent").messages) if "Sent" in mailbox.folders else 0
            drafts_count = len(mailbox.folders.get("Drafts").messages) if "Drafts" in mailbox.folders else 0
            trash_count = len(mailbox.folders.get("Trash").messages) if "Trash" in mailbox.folders else 0
            total_messages = len(mailbox.get_messages())
            attachment_size_mb = round(mailbox.total_attachment_size / (1024 * 1024), 2)
            
            summary_table.add_row([
                username,
                total_messages,
                inbox_count,
                sent_count,
                drafts_count,
                trash_count,
                mailbox.total_attachments,
                attachment_size_mb
            ])
        
        print(summary_table)
        
        # Detailed messages table (if requested)
        if show_messages:
            for username, mailbox in self.mailboxes.items():
                messages = mailbox.get_messages()
                if messages:
                    msg_table = PrettyTable(["#", "From", "To", "Subject", "Timestamp", "Folder"])
                    if markdown:
                        msg_table.set_style(MARKDOWN)
                    msg_table.align = "l"
                    msg_table.title = f"{username}'s Messages"
                    
                    for i, msg in enumerate(messages, 1):
                        # Find which folder the message is in
                        folder_name = "INBOX"  # Default
                        for folder, folder_obj in mailbox.folders.items():
                            if msg in folder_obj.messages:
                                folder_name = folder
                                break
                        
                        msg_table.add_row([
                            i,
                            msg.sender[:20] + "..." if len(msg.sender) > 20 else msg.sender,
                            ", ".join(msg.recipients)[:20] + "..." if len(", ".join(msg.recipients)) > 20 else ", ".join(msg.recipients),
                            msg.subject[:30] + "..." if len(msg.subject) > 30 else msg.subject,
                            msg.timestamp[:19] if msg.timestamp else "N/A",
                            folder_name
                        ])
                    
                    print(msg_table)

    def describe_state(self) -> Dict:
        """
        Produce a dictionary describing the current state of the MailboxManager.

        :return: Current state of this object and child objects.
        :rtype: Dict
        """
        total_attachments = sum(mailbox.total_attachments for mailbox in self.mailboxes.values())
        total_attachment_size = sum(mailbox.total_attachment_size for mailbox in self.mailboxes.values())
        
        state = {
            "total_mailboxes": len(self.mailboxes),
            "total_messages": sum(len(mailbox.get_messages()) for mailbox in self.mailboxes.values()),
            "total_attachments": total_attachments,
            "total_attachment_size": total_attachment_size,
            "total_attachment_size_mb": round(total_attachment_size / (1024 * 1024), 2),
            "mailboxes": {}
        }
        
        for username, mailbox in self.mailboxes.items():
            folder_info = {}
            for folder_name, folder in mailbox.folders.items():
                messages_with_attachments = sum(1 for msg in folder.messages if msg.has_attachments)
                folder_attachment_size = sum(
                    sum(att.file_size for att in msg.attachments)
                    for msg in folder.messages if msg.has_attachments
                )
                
                folder_info[folder_name] = {
                    "message_count": len(folder.messages),
                    "messages_with_attachments": messages_with_attachments,
                    "folder_attachment_size": folder_attachment_size,
                    "exists": folder.exists,
                    "recent": folder.recent,
                    "unseen": folder.unseen
                }
            
            attachment_stats = mailbox.get_attachment_statistics()
            
            state["mailboxes"][username] = {
                "total_messages": mailbox.total_messages,
                "attachment_statistics": attachment_stats,
                "attachment_cleanup_policy": mailbox.attachment_cleanup_policy,
                "folders": folder_info
            }
        
        return state