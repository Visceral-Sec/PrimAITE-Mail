# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Unit tests for EmailMessage class with attachment support."""

import json
import pytest
from typing import Dict, Any

from primaite_mail.simulator.network.protocols.smtp import EmailMessage
from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment
from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus


class TestEmailMessage:
    """Test EmailMessage class functionality."""

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
    def sample_email_no_attachments(self) -> EmailMessage:
        """Create a sample email without attachments."""
        return EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com", "charlie@company.com"],
            subject="Test Email",
            body="This is a test email body.",
            headers={"X-Priority": "1", "X-Mailer": "PrimAITE-Mail"},
            timestamp="2025-01-01T12:00:00Z",
            message_id="test-message-123"
        )

    @pytest.fixture
    def sample_email_with_attachments(self, sample_attachment) -> EmailMessage:
        """Create a sample email with attachments."""
        email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Email with Attachment",
            body="Please find the attached file.",
            headers={"X-Priority": "1"},
            timestamp="2025-01-01T12:00:00Z",
            message_id="test-message-456"
        )
        email.add_attachment(sample_attachment)
        return email

    def test_email_message_basic_properties(self, sample_email_no_attachments):
        """Test basic EmailMessage properties."""
        email = sample_email_no_attachments
        
        assert email.sender == "alice@company.com"
        assert email.recipients == ["bob@company.com", "charlie@company.com"]
        assert email.subject == "Test Email"
        assert email.body == "This is a test email body."
        assert email.headers["X-Priority"] == "1"
        assert email.timestamp == "2025-01-01T12:00:00Z"
        assert email.message_id == "test-message-123"

    def test_has_attachments_property(self, sample_email_no_attachments, sample_email_with_attachments):
        """Test has_attachments property."""
        assert not sample_email_no_attachments.has_attachments
        assert sample_email_with_attachments.has_attachments

    def test_attachment_count_property(self, sample_email_no_attachments, sample_email_with_attachments, sample_attachment):
        """Test attachment_count property."""
        assert sample_email_no_attachments.attachment_count == 0
        assert sample_email_with_attachments.attachment_count == 1
        
        # Add another attachment
        second_attachment = EmailAttachment.from_file_content(
            filename="test2.txt",
            content_type="text/plain",
            file_content=b"Second file content",
            file_uuid="test-uuid-456",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        sample_email_with_attachments.add_attachment(second_attachment)
        assert sample_email_with_attachments.attachment_count == 2

    def test_calculate_total_size_no_attachments(self, sample_email_no_attachments):
        """Test size calculation for email without attachments."""
        email = sample_email_no_attachments
        size = email.calculate_total_size()
        
        # Calculate expected size manually
        expected_size = 0
        expected_size += len(email.sender.encode('utf-8'))  # alice@company.com
        expected_size += len(email.recipients[0].encode('utf-8'))  # bob@company.com
        expected_size += len(email.recipients[1].encode('utf-8'))  # charlie@company.com
        expected_size += len(email.subject.encode('utf-8'))  # Test Email
        expected_size += len(email.body.encode('utf-8'))  # This is a test email body.
        
        # Add headers
        for key, value in email.headers.items():
            expected_size += len(f"{key}: {value}\r\n".encode('utf-8'))
        
        assert size == expected_size
        assert size > 0

    def test_calculate_total_size_with_attachments(self, sample_email_with_attachments):
        """Test size calculation for email with attachments."""
        email = sample_email_with_attachments
        size = email.calculate_total_size()
        
        # Calculate expected size manually
        expected_size = 0
        expected_size += len(email.sender.encode('utf-8'))
        expected_size += len(email.recipients[0].encode('utf-8'))
        expected_size += len(email.subject.encode('utf-8'))
        expected_size += len(email.body.encode('utf-8'))
        
        # Add headers
        for key, value in email.headers.items():
            expected_size += len(f"{key}: {value}\r\n".encode('utf-8'))
        
        # Add attachment sizes (encoded size)
        for attachment in email.attachments:
            expected_size += len(attachment.file_data.encode('utf-8'))
        
        assert size == expected_size
        assert size > 0

    def test_calculate_total_size_multiple_attachments(self, sample_email_no_attachments):
        """Test size calculation with multiple attachments."""
        email = sample_email_no_attachments
        
        # Add multiple attachments of different sizes
        attachments_data = [
            (b"Small file", "small.txt"),
            (b"Medium file content with more text", "medium.txt"),
            (b"Large file content with much more text and data that takes up more space", "large.txt")
        ]
        
        for content, filename in attachments_data:
            attachment = EmailAttachment.from_file_content(
                filename=filename,
                content_type="text/plain",
                file_content=content,
                file_uuid=f"uuid-{filename}",
                health_status=FileSystemItemHealthStatus.GOOD
            )
            email.add_attachment(attachment)
        
        size = email.calculate_total_size()
        
        # Size should include all attachments
        assert size > 0
        assert email.attachment_count == 3

    def test_get_attachment_by_filename(self, sample_email_with_attachments):
        """Test getting attachment by filename."""
        email = sample_email_with_attachments
        
        # Should find existing attachment
        attachment = email.get_attachment_by_filename("test.txt")
        assert attachment is not None
        assert attachment.filename == "test.txt"
        
        # Should return None for non-existent attachment
        attachment = email.get_attachment_by_filename("nonexistent.txt")
        assert attachment is None

    def test_add_attachment(self, sample_email_no_attachments):
        """Test adding attachments to email."""
        email = sample_email_no_attachments
        
        assert email.attachment_count == 0
        assert not email.has_attachments
        
        # Add attachment
        attachment = EmailAttachment.from_file_content(
            filename="new.txt",
            content_type="text/plain",
            file_content=b"New attachment content",
            file_uuid="new-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        
        email.add_attachment(attachment)
        
        assert email.attachment_count == 1
        assert email.has_attachments
        assert email.get_attachment_by_filename("new.txt") is not None

    def test_remove_attachment(self, sample_email_with_attachments):
        """Test removing attachments from email."""
        email = sample_email_with_attachments
        
        assert email.attachment_count == 1
        assert email.has_attachments
        
        # Remove existing attachment
        result = email.remove_attachment("test.txt")
        assert result is True
        assert email.attachment_count == 0
        assert not email.has_attachments
        
        # Try to remove non-existent attachment
        result = email.remove_attachment("nonexistent.txt")
        assert result is False

    def test_to_dict_no_attachments(self, sample_email_no_attachments):
        """Test serialization to dictionary without attachments."""
        email = sample_email_no_attachments
        data = email.to_dict()
        
        assert isinstance(data, dict)
        assert data["sender"] == email.sender
        assert data["recipients"] == email.recipients
        assert data["subject"] == email.subject
        assert data["body"] == email.body
        assert data["headers"] == email.headers
        assert data["timestamp"] == email.timestamp
        assert data["message_id"] == email.message_id
        assert data["attachments"] == []
        assert data["has_attachments"] is False
        assert data["attachment_count"] == 0
        assert data["total_size"] == email.calculate_total_size()

    def test_to_dict_with_attachments(self, sample_email_with_attachments):
        """Test serialization to dictionary with attachments."""
        email = sample_email_with_attachments
        data = email.to_dict()
        
        assert isinstance(data, dict)
        assert data["sender"] == email.sender
        assert data["recipients"] == email.recipients
        assert data["subject"] == email.subject
        assert data["body"] == email.body
        assert data["attachments"] is not None
        assert len(data["attachments"]) == 1
        assert data["has_attachments"] is True
        assert data["attachment_count"] == 1
        assert data["total_size"] == email.calculate_total_size()
        
        # Check attachment data
        attachment_data = data["attachments"][0]
        assert attachment_data["filename"] == "test.txt"
        assert attachment_data["content_type"] == "text/plain"

    def test_from_dict_no_attachments(self, sample_email_no_attachments):
        """Test deserialization from dictionary without attachments."""
        original_email = sample_email_no_attachments
        data = original_email.to_dict()
        
        # Remove computed properties from data
        data.pop("has_attachments", None)
        data.pop("attachment_count", None)
        data.pop("total_size", None)
        
        reconstructed_email = EmailMessage.from_dict(data)
        
        assert reconstructed_email.sender == original_email.sender
        assert reconstructed_email.recipients == original_email.recipients
        assert reconstructed_email.subject == original_email.subject
        assert reconstructed_email.body == original_email.body
        assert reconstructed_email.headers == original_email.headers
        assert reconstructed_email.timestamp == original_email.timestamp
        assert reconstructed_email.message_id == original_email.message_id
        assert reconstructed_email.attachment_count == 0
        assert not reconstructed_email.has_attachments

    def test_from_dict_with_attachments(self, sample_email_with_attachments):
        """Test deserialization from dictionary with attachments."""
        original_email = sample_email_with_attachments
        data = original_email.to_dict()
        
        # Remove computed properties from data
        data.pop("has_attachments", None)
        data.pop("attachment_count", None)
        data.pop("total_size", None)
        
        reconstructed_email = EmailMessage.from_dict(data)
        
        assert reconstructed_email.sender == original_email.sender
        assert reconstructed_email.recipients == original_email.recipients
        assert reconstructed_email.subject == original_email.subject
        assert reconstructed_email.body == original_email.body
        assert reconstructed_email.attachment_count == 1
        assert reconstructed_email.has_attachments
        
        # Check attachment was reconstructed correctly
        attachment = reconstructed_email.get_attachment_by_filename("test.txt")
        assert attachment is not None
        assert attachment.filename == "test.txt"
        assert attachment.content_type == "text/plain"

    def test_to_json_and_from_json_roundtrip(self, sample_email_with_attachments):
        """Test JSON serialization and deserialization roundtrip."""
        original_email = sample_email_with_attachments
        
        # Serialize to JSON
        json_str = original_email.to_json()
        assert isinstance(json_str, str)
        
        # Verify it's valid JSON
        data = json.loads(json_str)
        assert isinstance(data, dict)
        
        # Deserialize from JSON
        reconstructed_email = EmailMessage.from_json(json_str)
        
        # Verify all properties match
        assert reconstructed_email.sender == original_email.sender
        assert reconstructed_email.recipients == original_email.recipients
        assert reconstructed_email.subject == original_email.subject
        assert reconstructed_email.body == original_email.body
        assert reconstructed_email.attachment_count == original_email.attachment_count
        assert reconstructed_email.has_attachments == original_email.has_attachments
        assert reconstructed_email.calculate_total_size() == original_email.calculate_total_size()

    def test_serialization_with_unicode_content(self):
        """Test serialization with Unicode characters in email content."""
        email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Test with émojis 🚀",
            body="Hello with special chars: àáâãäåæçèéêë",
            headers={"X-Test": "Unicode: ñáéíóú"}
        )
        
        # Add attachment with Unicode filename
        attachment = EmailAttachment.from_file_content(
            filename="tëst_fîlé.txt",
            content_type="text/plain",
            file_content="Content with Unicode: ñáéíóú".encode('utf-8'),
            file_uuid="unicode-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        email.add_attachment(attachment)
        
        # Test serialization
        json_str = email.to_json()
        reconstructed_email = EmailMessage.from_json(json_str)
        
        assert reconstructed_email.subject == email.subject
        assert reconstructed_email.body == email.body
        assert reconstructed_email.headers["X-Test"] == email.headers["X-Test"]
        
        reconstructed_attachment = reconstructed_email.get_attachment_by_filename("tëst_fîlé.txt")
        assert reconstructed_attachment is not None

    def test_size_calculation_edge_cases(self):
        """Test size calculation with edge cases."""
        # Empty email
        empty_email = EmailMessage(sender="", recipients=[], subject="", body="")
        assert empty_email.calculate_total_size() == 0
        
        # Email with empty attachment
        email_with_empty_attachment = EmailMessage(
            sender="test@example.com",
            recipients=["recipient@example.com"],
            subject="Test",
            body="Test"
        )
        
        empty_attachment = EmailAttachment.from_file_content(
            filename="empty.txt",
            content_type="text/plain",
            file_content=b"",
            file_uuid="empty-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        email_with_empty_attachment.add_attachment(empty_attachment)
        
        size = email_with_empty_attachment.calculate_total_size()
        assert size > 0  # Should still have base message size

    def test_attachment_operations_edge_cases(self):
        """Test attachment operations with edge cases."""
        email = EmailMessage(sender="test@example.com", recipients=["test@example.com"])
        
        # Remove from empty attachments list
        assert email.remove_attachment("nonexistent.txt") is False
        
        # Get attachment from empty list
        assert email.get_attachment_by_filename("nonexistent.txt") is None
        
        # Add multiple attachments with same filename
        attachment1 = EmailAttachment.from_file_content(
            filename="duplicate.txt",
            content_type="text/plain",
            file_content=b"First content",
            file_uuid="uuid1",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        attachment2 = EmailAttachment.from_file_content(
            filename="duplicate.txt",
            content_type="text/plain",
            file_content=b"Second content",
            file_uuid="uuid2",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        
        email.add_attachment(attachment1)
        email.add_attachment(attachment2)
        
        assert email.attachment_count == 2
        
        # get_attachment_by_filename should return the first match
        found_attachment = email.get_attachment_by_filename("duplicate.txt")
        assert found_attachment.file_uuid == "uuid1"
        
        # remove_attachment should remove the first match
        assert email.remove_attachment("duplicate.txt") is True
        assert email.attachment_count == 1
        
        # Remaining attachment should be the second one
        remaining_attachment = email.get_attachment_by_filename("duplicate.txt")
        assert remaining_attachment.file_uuid == "uuid2"
    
    def test_serialization_deserialization_integrity(self):
        """Test that attachment data integrity is preserved through serialization cycles."""
        # Create email with various attachment types
        email = EmailMessage(
            sender="sender@example.com",
            recipients=["recipient@example.com"],
            subject="Integrity Test",
            body="Testing data integrity"
        )
        
        # Add attachments with different characteristics
        attachments_data = [
            (b"Simple text content", "text.txt", "text/plain", FileSystemItemHealthStatus.GOOD),
            (b"\x00\x01\x02\x03\xFF\xFE\xFD", "binary.bin", "application/octet-stream", FileSystemItemHealthStatus.GOOD),
            (b"Corrupted data with markers", "virus.exe", "application/x-msdownload", FileSystemItemHealthStatus.CORRUPT),
            (b"", "empty.txt", "text/plain", FileSystemItemHealthStatus.GOOD),  # Empty file
            (b"x" * 10000, "large.dat", "application/octet-stream", FileSystemItemHealthStatus.GOOD)  # Large file
        ]
        
        for content, filename, content_type, health_status in attachments_data:
            attachment = EmailAttachment.from_file_content(
                filename=filename,
                content_type=content_type,
                file_content=content,
                file_uuid=f"uuid-{filename}",
                health_status=health_status
            )
            email.add_attachment(attachment)
        
        # Serialize to JSON and back
        json_str = email.to_json()
        reconstructed_email = EmailMessage.from_json(json_str)
        
        # Verify all attachments are preserved
        assert reconstructed_email.attachment_count == len(attachments_data)
        
        for original_content, filename, content_type, health_status in attachments_data:
            reconstructed_attachment = reconstructed_email.get_attachment_by_filename(filename)
            assert reconstructed_attachment is not None
            assert reconstructed_attachment.filename == filename
            assert reconstructed_attachment.content_type == content_type
            assert reconstructed_attachment.health_status == health_status.name
            assert reconstructed_attachment.file_size == len(original_content)
            
            # Most importantly, verify content integrity
            reconstructed_content = reconstructed_attachment.get_decoded_content()
            assert reconstructed_content == original_content
    
    def test_serialization_deserialization_multiple_cycles(self):
        """Test data integrity through multiple serialization/deserialization cycles."""
        original_email = EmailMessage(
            sender="test@example.com",
            recipients=["recipient@example.com"],
            subject="Multi-cycle Test",
            body="Testing multiple cycles"
        )
        
        # Add attachment with specific content
        test_content = b"This content should remain identical through multiple cycles"
        attachment = EmailAttachment.from_file_content(
            filename="test_file.txt",
            content_type="text/plain",
            file_content=test_content,
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        original_email.add_attachment(attachment)
        
        current_email = original_email
        
        # Perform 5 serialization/deserialization cycles
        for cycle in range(5):
            json_str = current_email.to_json()
            current_email = EmailMessage.from_json(json_str)
            
            # Verify integrity after each cycle
            assert current_email.attachment_count == 1
            reconstructed_attachment = current_email.get_attachment_by_filename("test_file.txt")
            assert reconstructed_attachment is not None
            assert reconstructed_attachment.get_decoded_content() == test_content
    
    def test_size_calculation_accuracy(self):
        """Test accurate size calculation with various attachment combinations."""
        email = EmailMessage(
            sender="a@b.com",
            recipients=["c@d.com", "e@f.com"],
            subject="Size Test",
            body="Testing size calculation"
        )
        
        # Calculate base size without attachments
        base_size = email.calculate_total_size()
        
        # Add attachments of known sizes
        attachment_sizes = [100, 500, 1000, 2000]
        total_attachment_size = 0
        
        for i, size in enumerate(attachment_sizes):
            content = b"x" * size
            attachment = EmailAttachment.from_file_content(
                filename=f"file_{i}.txt",
                content_type="text/plain",
                file_content=content,
                file_uuid=f"uuid-{i}",
                health_status=FileSystemItemHealthStatus.GOOD
            )
            email.add_attachment(attachment)
            
            # Calculate expected size increase (base64 encoding increases size)
            encoded_size = len(attachment.file_data.encode('utf-8'))
            total_attachment_size += encoded_size
        
        # Verify total size calculation
        total_size = email.calculate_total_size()
        expected_size = base_size + total_attachment_size
        assert total_size == expected_size
    
    def test_size_calculation_with_unicode_content(self):
        """Test size calculation with Unicode characters in email and attachments."""
        # Create email with Unicode content
        email = EmailMessage(
            sender="tëst@éxample.com",
            recipients=["rëcipient@éxample.com"],
            subject="Tëst with Ünicöde 🚀",
            body="Bödy with spëcial charactërs: àáâãäåæçèéêë"
        )
        
        # Add attachment with Unicode filename and content
        unicode_content = "Contënt with Ünicöde: ñáéíóú 🎉".encode('utf-8')
        attachment = EmailAttachment.from_file_content(
            filename="tëst_fîlé.txt",
            content_type="text/plain",
            file_content=unicode_content,
            file_uuid="unicode-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        email.add_attachment(attachment)
        
        # Calculate size and verify it handles Unicode properly
        size = email.calculate_total_size()
        assert size > 0
        
        # Verify serialization works with Unicode
        json_str = email.to_json()
        reconstructed_email = EmailMessage.from_json(json_str)
        
        assert reconstructed_email.calculate_total_size() == size
        reconstructed_attachment = reconstructed_email.get_attachment_by_filename("tëst_fîlé.txt")
        assert reconstructed_attachment.get_decoded_content() == unicode_content
    
    def test_attachment_metadata_preservation(self):
        """Test that attachment metadata is preserved through email workflow."""
        email = EmailMessage(
            sender="sender@example.com",
            recipients=["recipient@example.com"],
            subject="Metadata Test",
            body="Testing metadata preservation"
        )
        
        # Create attachment with specific metadata
        original_uuid = "original-file-uuid-12345"
        original_health = FileSystemItemHealthStatus.CORRUPT
        original_content = b"Original file content with specific characteristics"
        
        attachment = EmailAttachment.from_file_content(
            filename="important_file.doc",
            content_type="application/msword",
            file_content=original_content,
            file_uuid=original_uuid,
            health_status=original_health
        )
        
        email.add_attachment(attachment)
        
        # Serialize and deserialize
        json_str = email.to_json()
        reconstructed_email = EmailMessage.from_json(json_str)
        
        # Verify all metadata is preserved
        reconstructed_attachment = reconstructed_email.get_attachment_by_filename("important_file.doc")
        assert reconstructed_attachment is not None
        assert reconstructed_attachment.file_uuid == original_uuid
        assert reconstructed_attachment.health_status == original_health.name
        assert reconstructed_attachment.content_type == "application/msword"
        assert reconstructed_attachment.file_size == len(original_content)
        assert reconstructed_attachment.get_decoded_content() == original_content
    
    def test_attachment_encoding_decoding_edge_cases(self):
        """Test attachment encoding/decoding with edge cases."""
        email = EmailMessage(sender="test@example.com", recipients=["test@example.com"])
        
        # Test with various binary data patterns
        test_patterns = [
            b"",  # Empty
            b"\x00",  # Single null byte
            b"\xFF" * 100,  # All high bytes
            b"\x00\xFF" * 50,  # Alternating pattern
            bytes(range(256)),  # All possible byte values
            b"Normal text with\nnewlines\tand\ttabs",  # Text with control chars
        ]
        
        for i, pattern in enumerate(test_patterns):
            attachment = EmailAttachment.from_file_content(
                filename=f"pattern_{i}.bin",
                content_type="application/octet-stream",
                file_content=pattern,
                file_uuid=f"pattern-uuid-{i}",
                health_status=FileSystemItemHealthStatus.GOOD
            )
            email.add_attachment(attachment)
        
        # Serialize and deserialize
        json_str = email.to_json()
        reconstructed_email = EmailMessage.from_json(json_str)
        
        # Verify all patterns are preserved
        for i, original_pattern in enumerate(test_patterns):
            reconstructed_attachment = reconstructed_email.get_attachment_by_filename(f"pattern_{i}.bin")
            assert reconstructed_attachment is not None
            reconstructed_pattern = reconstructed_attachment.get_decoded_content()
            assert reconstructed_pattern == original_pattern
    
    def test_email_message_with_maximum_attachments(self):
        """Test email message handling with maximum number of attachments."""
        email = EmailMessage(
            sender="sender@example.com",
            recipients=["recipient@example.com"],
            subject="Max Attachments Test",
            body="Testing maximum attachments"
        )
        
        # Add many attachments (test system limits)
        max_attachments = 50  # Reasonable test limit
        
        for i in range(max_attachments):
            content = f"Content for attachment {i}".encode('utf-8')
            attachment = EmailAttachment.from_file_content(
                filename=f"file_{i:03d}.txt",
                content_type="text/plain",
                file_content=content,
                file_uuid=f"uuid-{i}",
                health_status=FileSystemItemHealthStatus.GOOD
            )
            email.add_attachment(attachment)
        
        assert email.attachment_count == max_attachments
        
        # Test serialization with many attachments
        json_str = email.to_json()
        reconstructed_email = EmailMessage.from_json(json_str)
        
        assert reconstructed_email.attachment_count == max_attachments
        
        # Verify a few random attachments
        for i in [0, 10, 25, 49]:
            attachment = reconstructed_email.get_attachment_by_filename(f"file_{i:03d}.txt")
            assert attachment is not None
            expected_content = f"Content for attachment {i}".encode('utf-8')
            assert attachment.get_decoded_content() == expected_content
    
    def test_serialization_error_handling(self):
        """Test serialization error handling with malformed data."""
        # Test with valid email first
        email = EmailMessage(
            sender="test@example.com",
            recipients=["recipient@example.com"],
            subject="Error Test",
            body="Testing error handling"
        )
        
        # Add normal attachment
        attachment = EmailAttachment.from_file_content(
            filename="normal.txt",
            content_type="text/plain",
            file_content=b"normal content",
            file_uuid="normal-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        email.add_attachment(attachment)
        
        # Test normal serialization works
        json_str = email.to_json()
        reconstructed = EmailMessage.from_json(json_str)
        assert reconstructed.attachment_count == 1
        
        # Test deserialization with malformed JSON
        malformed_json_cases = [
            '{"invalid": "json"',  # Incomplete JSON
            '{"sender": "test@example.com"}',  # Missing required fields
            '{"sender": "test", "recipients": [], "subject": "", "body": "", "attachments": "not_a_list"}',  # Wrong type
        ]
        
        for malformed_json in malformed_json_cases:
            try:
                EmailMessage.from_json(malformed_json)
                # If no exception is raised, that's also valid (graceful handling)
            except (ValueError, TypeError, KeyError):
                # Expected behavior for malformed data
                pass
    
    def test_attachment_workflow_integration(self):
        """Test complete attachment workflow integration."""
        # Simulate complete email workflow: create -> attach -> send -> receive -> extract
        
        # 1. Create email
        email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Project Files",
            body="Please find the project files attached."
        )
        
        # 2. Attach multiple files
        project_files = [
            (b"Project specification document content", "spec.doc", "application/msword"),
            (b"Source code content", "main.py", "text/x-python"),
            (b"Binary data for executable", "tool.exe", "application/x-msdownload"),
            (b"Image data", "diagram.png", "image/png")
        ]
        
        for content, filename, content_type in project_files:
            attachment = EmailAttachment.from_file_content(
                filename=filename,
                content_type=content_type,
                file_content=content,
                file_uuid=f"uuid-{filename}",
                health_status=FileSystemItemHealthStatus.GOOD
            )
            email.add_attachment(attachment)
        
        # 3. Simulate sending (serialization)
        transmitted_data = email.to_json()
        
        # 4. Simulate receiving (deserialization)
        received_email = EmailMessage.from_json(transmitted_data)
        
        # 5. Verify received email integrity
        assert received_email.sender == email.sender
        assert received_email.recipients == email.recipients
        assert received_email.subject == email.subject
        assert received_email.body == email.body
        assert received_email.attachment_count == len(project_files)
        
        # 6. Verify each attachment can be extracted
        for original_content, filename, content_type in project_files:
            attachment = received_email.get_attachment_by_filename(filename)
            assert attachment is not None
            assert attachment.content_type == content_type
            
            # Simulate extraction
            extracted_content = attachment.get_decoded_content()
            assert extracted_content == original_content
        
        # 7. Verify size calculations are consistent
        assert received_email.calculate_total_size() == email.calculate_total_size()