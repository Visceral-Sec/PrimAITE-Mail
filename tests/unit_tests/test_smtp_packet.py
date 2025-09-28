# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Unit tests for SMTPPacket class with attachment support."""

import pytest
from typing import Dict, Any

from primaite_mail.simulator.network.protocols.smtp import SMTPPacket, SMTPCommand, SMTPStatusCode, EmailMessage
from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment
from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus


class TestSMTPPacket:
    """Test SMTPPacket class functionality."""

    @pytest.fixture
    def sample_attachment(self) -> EmailAttachment:
        """Create a sample attachment for testing."""
        return EmailAttachment.from_file_content(
            filename="test.txt",
            content_type="text/plain",
            file_content=b"Hello, World!",
            file_uuid="test-uuid-123",
            health_status=FileSystemItemHealthStatus.GOOD
        )

    @pytest.fixture
    def large_attachment(self) -> EmailAttachment:
        """Create a large attachment for testing."""
        # Create 2MB of data
        large_content = b"A" * (2 * 1024 * 1024)
        return EmailAttachment.from_file_content(
            filename="large_file.bin",
            content_type="application/octet-stream",
            file_content=large_content,
            file_uuid="large-uuid-456",
            health_status=FileSystemItemHealthStatus.GOOD
        )

    @pytest.fixture
    def corrupted_attachment(self) -> EmailAttachment:
        """Create a corrupted attachment for testing."""
        return EmailAttachment.from_file_content(
            filename="virus.exe",
            content_type="application/x-executable",
            file_content=b"Malicious content",
            file_uuid="virus-uuid-789",
            health_status=FileSystemItemHealthStatus.CORRUPT
        )

    @pytest.fixture
    def simple_email(self) -> EmailMessage:
        """Create a simple email without attachments."""
        return EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Simple Test",
            body="This is a simple test email."
        )

    @pytest.fixture
    def email_with_attachment(self, sample_attachment) -> EmailMessage:
        """Create an email with a small attachment."""
        email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Email with Attachment",
            body="Please find the attached file."
        )
        email.add_attachment(sample_attachment)
        return email

    @pytest.fixture
    def email_with_large_attachment(self, large_attachment) -> EmailMessage:
        """Create an email with a large attachment."""
        email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Large Attachment",
            body="Large file attached."
        )
        email.add_attachment(large_attachment)
        return email

    def test_smtp_packet_basic_properties(self):
        """Test basic SMTPPacket properties."""
        packet = SMTPPacket(
            command=SMTPCommand.HELO,
            arguments="client.example.com",
            session_id="session-123"
        )
        
        assert packet.command == SMTPCommand.HELO
        assert packet.arguments == "client.example.com"
        assert packet.session_id == "session-123"
        assert packet.max_message_size == 50 * 1024 * 1024  # Default 50MB
        assert packet.chunk_size == 1024 * 1024  # Default 1MB

    def test_smtp_packet_response_properties(self):
        """Test SMTP response packet properties."""
        packet = SMTPPacket(
            status_code=SMTPStatusCode.OK_COMPLETED,
            message="Command completed successfully"
        )
        
        assert packet.status_code == SMTPStatusCode.OK_COMPLETED
        assert packet.message == "Command completed successfully"

    def test_calculate_packet_size_simple(self, simple_email):
        """Test packet size calculation for simple email."""
        packet = SMTPPacket(
            command=SMTPCommand.DATA,
            email_data=simple_email,
            session_id="test-session"
        )
        
        size = packet.calculate_packet_size()
        assert size > 0
        
        # Size should include command, email data, and session ID
        expected_size = len("DATA".encode('utf-8'))
        expected_size += simple_email.calculate_total_size()
        expected_size += len("test-session".encode('utf-8'))
        
        assert size == expected_size

    def test_calculate_packet_size_with_attachment(self, email_with_attachment):
        """Test packet size calculation for email with attachment."""
        packet = SMTPPacket(
            command=SMTPCommand.DATA,
            email_data=email_with_attachment
        )
        
        size = packet.calculate_packet_size()
        assert size > 0
        
        # Size should be larger than just the email due to attachment
        email_size = email_with_attachment.calculate_total_size()
        assert size >= email_size

    def test_is_large_message_simple_email(self, simple_email):
        """Test large message detection for simple email."""
        packet = SMTPPacket(email_data=simple_email)
        assert not packet.is_large_message()

    def test_is_large_message_with_attachment(self, email_with_attachment):
        """Test large message detection for email with attachment."""
        packet = SMTPPacket(email_data=email_with_attachment)
        # Small attachment should still be considered "large" because it has attachments
        assert packet.is_large_message()

    def test_is_large_message_with_large_attachment(self, email_with_large_attachment):
        """Test large message detection for email with large attachment."""
        packet = SMTPPacket(email_data=email_with_large_attachment)
        assert packet.is_large_message()

    def test_get_attachment_headers_no_attachments(self, simple_email):
        """Test attachment headers for email without attachments."""
        packet = SMTPPacket(email_data=simple_email)
        headers = packet.get_attachment_headers()
        
        assert headers == {}

    def test_get_attachment_headers_with_attachment(self, email_with_attachment):
        """Test attachment headers for email with attachment."""
        packet = SMTPPacket(email_data=email_with_attachment)
        headers = packet.get_attachment_headers()
        
        assert "X-Attachment-Count" in headers
        assert headers["X-Attachment-Count"] == "1"
        
        assert "X-Attachment-Total-Size" in headers
        assert int(headers["X-Attachment-Total-Size"]) > 0
        
        assert "X-Attachment-Filenames" in headers
        assert "test.txt" in headers["X-Attachment-Filenames"]
        
        assert "X-Attachment-Content-Types" in headers
        assert "text/plain" in headers["X-Attachment-Content-Types"]

    def test_get_attachment_headers_with_corrupted_attachment(self, corrupted_attachment):
        """Test attachment headers for email with corrupted attachment."""
        email = EmailMessage(
            sender="attacker@evil.com",
            recipients=["victim@company.com"],
            subject="Malicious Email",
            body="Don't open the attachment!"
        )
        email.add_attachment(corrupted_attachment)
        
        packet = SMTPPacket(email_data=email)
        headers = packet.get_attachment_headers()
        
        assert "X-Attachment-Health-Warning" in headers
        assert "Contains potentially corrupted files" in headers["X-Attachment-Health-Warning"]
        
        assert "X-Attachment-Health-Status" in headers
        assert "CORRUPT" in headers["X-Attachment-Health-Status"]

    def test_get_attachment_headers_multiple_attachments(self, sample_attachment, corrupted_attachment):
        """Test attachment headers for email with multiple attachments."""
        email = EmailMessage(
            sender="sender@company.com",
            recipients=["recipient@company.com"],
            subject="Multiple Attachments",
            body="Multiple files attached."
        )
        email.add_attachment(sample_attachment)
        email.add_attachment(corrupted_attachment)
        
        packet = SMTPPacket(email_data=email)
        headers = packet.get_attachment_headers()
        
        assert headers["X-Attachment-Count"] == "2"
        assert "test.txt" in headers["X-Attachment-Filenames"]
        assert "virus.exe" in headers["X-Attachment-Filenames"]
        assert "text/plain" in headers["X-Attachment-Content-Types"]
        assert "application/x-executable" in headers["X-Attachment-Content-Types"]
        assert "X-Attachment-Health-Warning" in headers

    def test_apply_attachment_headers(self, email_with_attachment):
        """Test applying attachment headers to email data."""
        packet = SMTPPacket(email_data=email_with_attachment)
        
        # Initially no attachment headers
        assert "X-Attachment-Count" not in email_with_attachment.headers
        
        # Apply attachment headers
        packet.apply_attachment_headers()
        
        # Headers should now be present
        assert "X-Attachment-Count" in email_with_attachment.headers
        assert email_with_attachment.headers["X-Attachment-Count"] == "1"

    def test_validate_message_size_small_message(self, simple_email):
        """Test message size validation for small message."""
        packet = SMTPPacket(email_data=simple_email)
        is_valid, error_msg = packet.validate_message_size()
        
        assert is_valid is True
        assert error_msg is None

    def test_validate_message_size_large_message(self, email_with_large_attachment):
        """Test message size validation for large message."""
        # Set a small max message size to trigger validation failure
        packet = SMTPPacket(
            email_data=email_with_large_attachment,
            max_message_size=1024  # 1KB limit
        )
        
        is_valid, error_msg = packet.validate_message_size()
        
        assert is_valid is False
        assert error_msg is not None
        assert "exceeds maximum allowed" in error_msg

    def test_validate_message_size_no_email_data(self):
        """Test message size validation with no email data."""
        packet = SMTPPacket(command=SMTPCommand.HELO)
        is_valid, error_msg = packet.validate_message_size()
        
        assert is_valid is True
        assert error_msg is None

    def test_get_processing_chunks_small_message(self, simple_email):
        """Test processing chunks for small message."""
        packet = SMTPPacket(email_data=simple_email)
        chunks = packet.get_processing_chunks()
        
        assert len(chunks) == 1
        assert chunks[0]["chunk_id"] == 0
        assert chunks[0]["is_final"] is True

    def test_get_processing_chunks_large_message(self, email_with_large_attachment):
        """Test processing chunks for large message."""
        packet = SMTPPacket(
            email_data=email_with_large_attachment,
            chunk_size=1024 * 1024  # 1MB chunks
        )
        
        chunks = packet.get_processing_chunks()
        
        assert len(chunks) > 1  # Should be split into multiple chunks
        assert chunks[0]["chunk_id"] == 0
        assert chunks[-1]["is_final"] is True
        
        # Check chunk sizes
        for i, chunk in enumerate(chunks[:-1]):  # All but last chunk
            assert chunk["size"] == packet.chunk_size
        
        # Last chunk might be smaller
        assert chunks[-1]["size"] <= packet.chunk_size

    def test_to_dict_simple_packet(self, simple_email):
        """Test serialization to dictionary for simple packet."""
        packet = SMTPPacket(
            command=SMTPCommand.DATA,
            email_data=simple_email,
            session_id="test-session"
        )
        
        data = packet.to_dict()
        
        assert isinstance(data, dict)
        assert data["command"] == "DATA"
        assert data["email_data"] is not None
        assert data["session_id"] == "test-session"
        assert data["packet_size"] > 0
        assert data["is_large_message"] is False
        assert data["attachment_headers"] == {}

    def test_to_dict_packet_with_attachments(self, email_with_attachment):
        """Test serialization to dictionary for packet with attachments."""
        packet = SMTPPacket(
            command=SMTPCommand.DATA,
            email_data=email_with_attachment
        )
        
        data = packet.to_dict()
        
        assert data["is_large_message"] is True
        assert len(data["attachment_headers"]) > 0
        assert "X-Attachment-Count" in data["attachment_headers"]

    def test_from_dict_roundtrip(self, email_with_attachment):
        """Test dictionary serialization and deserialization roundtrip."""
        original_packet = SMTPPacket(
            command=SMTPCommand.DATA,
            arguments="test arguments",
            status_code=SMTPStatusCode.OK_COMPLETED,
            message="Success",
            email_data=email_with_attachment,
            session_id="test-session"
        )
        
        # Serialize to dict
        data = original_packet.to_dict()
        
        # Remove computed fields that aren't part of the model
        data.pop("packet_size", None)
        data.pop("is_large_message", None)
        data.pop("attachment_headers", None)
        
        # Deserialize from dict
        reconstructed_packet = SMTPPacket.from_dict(data)
        
        # Verify properties match
        assert reconstructed_packet.command == original_packet.command
        assert reconstructed_packet.arguments == original_packet.arguments
        assert reconstructed_packet.status_code == original_packet.status_code
        assert reconstructed_packet.message == original_packet.message
        assert reconstructed_packet.session_id == original_packet.session_id
        assert reconstructed_packet.email_data.sender == original_packet.email_data.sender
        assert reconstructed_packet.email_data.attachment_count == original_packet.email_data.attachment_count

    def test_packet_size_calculation_edge_cases(self):
        """Test packet size calculation with edge cases."""
        # Empty packet
        empty_packet = SMTPPacket()
        assert empty_packet.calculate_packet_size() == 0
        
        # Packet with only command
        command_packet = SMTPPacket(command=SMTPCommand.NOOP)
        assert command_packet.calculate_packet_size() == len("NOOP".encode('utf-8'))
        
        # Packet with only status code
        status_packet = SMTPPacket(status_code=SMTPStatusCode.OK_COMPLETED)
        assert status_packet.calculate_packet_size() == len("250".encode('utf-8'))

    def test_attachment_headers_edge_cases(self):
        """Test attachment headers with edge cases."""
        # Email with empty attachment list
        email = EmailMessage(
            sender="test@example.com",
            recipients=["recipient@example.com"],
            attachments=[]
        )
        packet = SMTPPacket(email_data=email)
        headers = packet.get_attachment_headers()
        assert headers == {}
        
        # Packet with no email data
        packet_no_email = SMTPPacket(command=SMTPCommand.HELO)
        headers = packet_no_email.get_attachment_headers()
        assert headers == {}

    def test_custom_size_limits(self, simple_email):
        """Test custom size limits for packets."""
        # Custom max message size
        packet = SMTPPacket(
            email_data=simple_email,
            max_message_size=1024,  # 1KB
            chunk_size=512  # 512 bytes
        )
        
        assert packet.max_message_size == 1024
        assert packet.chunk_size == 512
        
        # Test validation with custom limit
        is_valid, error_msg = packet.validate_message_size()
        # Simple email should still be valid even with small limit
        assert is_valid is True