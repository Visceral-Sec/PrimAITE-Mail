"""Unit tests for mailbox functionality."""

import pytest
from primaite_mail.simulator.software.mailbox import Mailbox, MailboxManager
from primaite_mail.simulator.network.protocols.smtp import EmailMessage
from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment
from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus


class TestMailbox:
    """Test cases for Mailbox class."""

    def test_mailbox_creation(self):
        """Test mailbox creation with default folders."""
        mailbox = Mailbox(username="testuser")
        
        assert mailbox.username == "testuser"
        assert "INBOX" in mailbox.folders
        assert "Sent" in mailbox.folders
        assert "Drafts" in mailbox.folders
        assert "Trash" in mailbox.folders
        assert mailbox.total_messages == 0

    def test_add_message(self, sample_email):
        """Test adding a message to mailbox."""
        mailbox = Mailbox(username="testuser")
        
        success = mailbox.add_message(sample_email)
        assert success is True
        assert mailbox.total_messages == 1
        assert len(mailbox.folders["INBOX"].messages) == 1
        assert mailbox.folders["INBOX"].exists == 1

    def test_add_message_to_specific_folder(self, sample_email):
        """Test adding a message to a specific folder."""
        mailbox = Mailbox(username="testuser")
        
        success = mailbox.add_message(sample_email, "Sent")
        assert success is True
        assert len(mailbox.folders["Sent"].messages) == 1
        assert len(mailbox.folders["INBOX"].messages) == 0

    def test_get_messages(self, sample_email):
        """Test retrieving messages from mailbox."""
        mailbox = Mailbox(username="testuser")
        mailbox.add_message(sample_email)
        
        messages = mailbox.get_messages()
        assert len(messages) == 1
        assert messages[0].sender == sample_email.sender

    def test_delete_message(self, sample_email):
        """Test deleting a message from mailbox."""
        mailbox = Mailbox(username="testuser")
        mailbox.add_message(sample_email)
        
        # Get the message ID
        messages = mailbox.get_messages()
        message_id = messages[0].message_id
        
        success = mailbox.delete_message(message_id)
        assert success is True
        assert mailbox.total_messages == 0
        assert len(mailbox.folders["INBOX"].messages) == 0

    def test_create_folder(self):
        """Test creating a new folder."""
        mailbox = Mailbox(username="testuser")
        
        success = mailbox.create_folder("Work")
        assert success is True
        assert "Work" in mailbox.folders

    def test_delete_folder(self):
        """Test deleting a custom folder."""
        mailbox = Mailbox(username="testuser")
        mailbox.create_folder("Work")
        
        success = mailbox.delete_folder("Work")
        assert success is True
        assert "Work" not in mailbox.folders

    def test_cannot_delete_default_folders(self):
        """Test that default folders cannot be deleted."""
        mailbox = Mailbox(username="testuser")
        
        for folder in ["INBOX", "Sent", "Drafts", "Trash"]:
            success = mailbox.delete_folder(folder)
            assert success is False
            assert folder in mailbox.folders

    def test_mailbox_attachment_tracking(self):
        """Test attachment tracking in mailbox."""
        mailbox = Mailbox(username="testuser")
        
        # Initially no attachments
        assert mailbox.total_attachments == 0
        assert mailbox.total_attachment_size == 0
        
        # Create email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",  # Base64 "Test"
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachment",
            body="Test email",
            attachments=[attachment]
        )
        
        # Add email and check tracking
        mailbox.add_message(email)
        assert mailbox.total_attachments == 1
        assert mailbox.total_attachment_size == 1024
        
    def test_attachment_statistics(self):
        """Test attachment statistics calculation."""
        mailbox = Mailbox(username="testuser")
        
        # Add email with multiple attachments
        attachments = [
            EmailAttachment(
                filename="doc1.pdf",
                content_type="application/pdf",
                file_size=1024,
                file_data="VGVzdA==",
                file_uuid="uuid1",
                health_status=FileSystemItemHealthStatus.GOOD.name
            ),
            EmailAttachment(
                filename="doc2.txt",
                content_type="text/plain",
                file_size=512,
                file_data="VGVzdA==",
                file_uuid="uuid2",
                health_status=FileSystemItemHealthStatus.GOOD.name
            )
        ]
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachments",
            body="Test email",
            attachments=attachments
        )
        
        mailbox.add_message(email)
        
        stats = mailbox.get_attachment_statistics()
        assert stats["total_attachments"] == 2
        assert stats["total_attachment_size"] == 1536  # 1024 + 512
        assert stats["messages_with_attachments"] == 1
        assert stats["average_attachment_size"] == 768  # 1536 / 2
        
    def test_delete_message_with_attachments(self):
        """Test deleting message updates attachment statistics."""
        mailbox = Mailbox(username="testuser")
        
        # Add email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachment",
            body="Test email",
            attachments=[attachment]
        )
        
        mailbox.add_message(email)
        assert mailbox.total_attachments == 1
        assert mailbox.total_attachment_size == 1024
        
        # Delete message
        messages = mailbox.get_messages()
        message_id = messages[0].message_id
        mailbox.delete_message(message_id)
        
        # Check statistics updated
        assert mailbox.total_attachments == 0
        assert mailbox.total_attachment_size == 0
        
    def test_get_messages_with_attachments(self):
        """Test filtering messages with attachments."""
        mailbox = Mailbox(username="testuser")
        
        # Add email without attachment
        email_no_att = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="No attachment",
            body="Test email"
        )
        mailbox.add_message(email_no_att)
        
        # Add email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email_with_att = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="With attachment",
            body="Test email",
            attachments=[attachment]
        )
        mailbox.add_message(email_with_att)
        
        # Test filtering
        all_messages = mailbox.get_messages()
        messages_with_attachments = mailbox.get_messages_with_attachments()
        
        assert len(all_messages) == 2
        assert len(messages_with_attachments) == 1
        assert messages_with_attachments[0].subject == "With attachment"


class TestMailboxManager:
    """Test cases for MailboxManager class."""

    def test_create_mailbox(self):
        """Test creating a new mailbox."""
        manager = MailboxManager()
        
        success = manager.create_mailbox("testuser")
        assert success is True
        assert "testuser" in manager.mailboxes

    def test_cannot_create_duplicate_mailbox(self):
        """Test that duplicate mailboxes cannot be created."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        success = manager.create_mailbox("testuser")
        assert success is False

    def test_get_mailbox(self):
        """Test retrieving a mailbox."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        mailbox = manager.get_mailbox("testuser")
        assert mailbox is not None
        assert mailbox.username == "testuser"

    def test_get_nonexistent_mailbox(self):
        """Test retrieving a non-existent mailbox."""
        manager = MailboxManager()
        
        mailbox = manager.get_mailbox("nonexistent")
        assert mailbox is None

    def test_delete_mailbox(self):
        """Test deleting a mailbox."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        success = manager.delete_mailbox("testuser")
        assert success is True
        assert "testuser" not in manager.mailboxes

    def test_get_mailbox_messages_request(self):
        """Test get_mailbox_messages request handler."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        # Add email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachment",
            body="Test email",
            attachments=[attachment]
        )
        
        mailbox = manager.get_mailbox("testuser")
        mailbox.add_message(email)
        
        # Test request
        response = manager.apply_request(["get_mailbox_messages", {
            "username": "testuser",
            "folder": "INBOX",
            "include_attachments": True
        }], {})
        
        assert response.status == "success"
        assert response.data["message_count"] == 1
        assert response.data["messages"][0]["has_attachments"] is True
        assert response.data["messages"][0]["attachment_count"] == 1
        assert "attachments" in response.data["messages"][0]

    def test_get_message_attachments_request(self):
        """Test get_message_attachments request handler."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        # Add email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachment",
            body="Test email",
            attachments=[attachment]
        )
        
        mailbox = manager.get_mailbox("testuser")
        mailbox.add_message(email)
        
        # Get message ID
        messages = mailbox.get_messages()
        message_id = messages[0].message_id
        
        # Test request
        response = manager.apply_request(["get_message_attachments", {
            "username": "testuser",
            "message_id": message_id,
            "folder": "INBOX"
        }], {})
        
        assert response.status == "success"
        assert response.data["has_attachments"] is True
        assert response.data["attachment_count"] == 1
        assert response.data["total_attachment_size"] == 1024
        assert len(response.data["attachments"]) == 1
        assert response.data["attachments"][0]["filename"] == "test.pdf"

    def test_mailbox_stats_request(self):
        """Test mailbox_stats request handler."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        # Add email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachment",
            body="Test email",
            attachments=[attachment]
        )
        
        mailbox = manager.get_mailbox("testuser")
        mailbox.add_message(email)
        
        # Test request
        response = manager.apply_request(["mailbox_stats", {
            "username": "testuser"
        }], {})
        
        assert response.status == "success"
        assert response.data["total_messages"] == 1
        assert response.data["attachment_statistics"]["total_attachments"] == 1
        assert response.data["attachment_statistics"]["total_attachment_size"] == 1024
        assert "storage_usage" in response.data
        assert "cleanup_policy" in response.data

    def test_delete_message_request_with_attachments(self):
        """Test delete_message request handler with attachment cleanup."""
        manager = MailboxManager()
        manager.create_mailbox("testuser")
        
        # Add email with attachment
        attachment = EmailAttachment(
            filename="test.pdf",
            content_type="application/pdf",
            file_size=1024,
            file_data="VGVzdA==",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD.name
        )
        
        email = EmailMessage(
            sender="sender@test.com",
            recipients=["testuser@test.com"],
            subject="Test with attachment",
            body="Test email",
            attachments=[attachment]
        )
        
        mailbox = manager.get_mailbox("testuser")
        mailbox.add_message(email)
        
        # Get message ID
        messages = mailbox.get_messages()
        message_id = messages[0].message_id
        
        # Test delete request
        response = manager.apply_request(["delete_message", {
            "username": "testuser",
            "message_id": message_id,
            "folder": "INBOX"
        }], {})
        
        assert response.status == "success"
        assert response.data["had_attachments"] is True
        assert response.data["attachments_cleaned"] == 1