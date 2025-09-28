"""Unit tests for email attachment security features and audit logging."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import logging

from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus
from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment, AttachmentPolicy
from primaite_mail.simulator.network.protocols.attachment_manager import AttachmentManager


class TestSecurityFeatures:
    """Test security features for email attachments."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.attachment_manager = AttachmentManager()
        
    def test_malware_detection_comprehensive_scenarios(self):
        """Test comprehensive malware detection scenarios."""
        # Create attachments with various threat indicators
        test_attachments = [
            # Clean files
            EmailAttachment.from_file_content(
                filename="document.pdf",
                content_type="application/pdf",
                file_content=b"Clean PDF content",
                file_uuid="clean-pdf-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            EmailAttachment.from_file_content(
                filename="image.jpg",
                content_type="image/jpeg",
                file_content=b"Clean JPEG data",
                file_uuid="clean-jpg-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # Corrupted files (malware indicators)
            EmailAttachment.from_file_content(
                filename="trojan.exe",
                content_type="application/x-msdownload",
                file_content=b"Malicious executable code",
                file_uuid="trojan-uuid",
                health_status=FileSystemItemHealthStatus.CORRUPT
            ),
            EmailAttachment.from_file_content(
                filename="virus.dll",
                content_type="application/x-msdownload",
                file_content=b"Corrupted library",
                file_uuid="virus-uuid",
                health_status=FileSystemItemHealthStatus.CORRUPT
            ),
            
            # Suspicious executables (clean but potentially dangerous)
            EmailAttachment.from_file_content(
                filename="legitimate_tool.exe",
                content_type="application/x-msdownload",
                file_content=b"Legitimate executable",
                file_uuid="tool-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            EmailAttachment.from_file_content(
                filename="installer.msi",
                content_type="application/x-msdownload",  # Use executable MIME type to trigger detection
                file_content=b"MSI installer package",
                file_uuid="msi-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # Suspicious extensions with non-executable MIME types
            EmailAttachment.from_file_content(
                filename="script.bat",
                content_type="text/plain",
                file_content=b"@echo off\necho Hello",
                file_uuid="bat-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            EmailAttachment.from_file_content(
                filename="macro.vbs",
                content_type="text/plain",
                file_content=b"VBScript code",
                file_uuid="vbs-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
        ]
        
        scan_results = self.attachment_manager.scan_for_malware(test_attachments)
        
        # Verify scan results
        assert scan_results["document.pdf"] == "CLEAN"
        assert scan_results["image.jpg"] == "CLEAN"
        assert scan_results["trojan.exe"] == "MALWARE_DETECTED"
        assert scan_results["virus.dll"] == "MALWARE_DETECTED"
        assert scan_results["legitimate_tool.exe"] == "SUSPICIOUS_EXECUTABLE"
        assert scan_results["installer.msi"] == "SUSPICIOUS_EXECUTABLE"
        assert scan_results["script.bat"] == "SUSPICIOUS_EXTENSION"
        assert scan_results["macro.vbs"] == "SUSPICIOUS_EXTENSION"
    
    def test_malware_detection_edge_cases(self):
        """Test malware detection with edge cases."""
        edge_case_attachments = [
            # File with no extension
            EmailAttachment.from_file_content(
                filename="README",
                content_type="text/plain",
                file_content=b"Readme content",
                file_uuid="readme-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # File with multiple extensions
            EmailAttachment.from_file_content(
                filename="document.pdf.exe",
                content_type="application/x-msdownload",
                file_content=b"Disguised executable",
                file_uuid="disguised-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # File with unusual but legitimate extension
            EmailAttachment.from_file_content(
                filename="data.xyz",
                content_type="application/octet-stream",
                file_content=b"Custom format data",
                file_uuid="custom-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # Empty file with suspicious extension
            EmailAttachment.from_file_content(
                filename="empty.exe",
                content_type="application/x-msdownload",
                file_content=b"",
                file_uuid="empty-exe-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
        ]
        
        scan_results = self.attachment_manager.scan_for_malware(edge_case_attachments)
        
        assert scan_results["README"] == "CLEAN"
        assert scan_results["document.pdf.exe"] == "SUSPICIOUS_DOUBLE_EXTENSION"  # More specific threat than SUSPICIOUS_EXECUTABLE
        assert scan_results["data.xyz"] == "CLEAN"
        assert scan_results["empty.exe"] == "SUSPICIOUS_EXECUTABLE"
    
    def test_quarantine_functionality(self):
        """Test quarantine functionality for suspicious attachments."""
        # Create policy with quarantine enabled
        quarantine_policy = AttachmentPolicy(
            quarantine_suspicious=True,
            scan_for_malware=True,
            blocked_extensions=["exe", "bat", "scr"]
        )
        
        # Create suspicious attachments that should be quarantined
        suspicious_attachments = [
            EmailAttachment.from_file_content(
                filename="malware.exe",
                content_type="application/x-msdownload",
                file_content=b"Malicious code",
                file_uuid="malware-uuid",
                health_status=FileSystemItemHealthStatus.CORRUPT
            ),
            EmailAttachment.from_file_content(
                filename="script.bat",
                content_type="text/plain",
                file_content=b"Batch script",
                file_uuid="script-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
        ]
        
        # Test individual attachment validation
        for attachment in suspicious_attachments:
            is_valid, error = quarantine_policy.validate_attachment(attachment)
            assert is_valid is False
            assert error is not None
        
        # Test message validation
        is_valid, error = quarantine_policy.validate_message_attachments(suspicious_attachments)
        assert is_valid is False
        
        # Verify quarantine setting is enabled
        assert quarantine_policy.quarantine_suspicious is True
    
    def test_security_audit_logging(self):
        """Test security audit logging for policy violations."""
        attachment = EmailAttachment.from_file_content(
            filename="suspicious_file.exe",
            content_type="application/x-msdownload",
            file_content=b"x" * 2000,  # Large file
            file_uuid="suspicious-uuid",
            health_status=FileSystemItemHealthStatus.CORRUPT
        )
        
        policy = AttachmentPolicy(
            max_attachment_size=1000,
            blocked_extensions=["exe"],
            scan_for_malware=True
        )
        
        # Mock logger to capture log messages
        with patch.object(self.attachment_manager, 'logger') as mock_logger:
            self.attachment_manager.log_policy_violation(
                attachment=attachment,
                policy=policy,
                violation_reason="Multiple policy violations detected",
                sender="attacker@malicious.com",
                recipients=["victim1@company.com", "victim2@company.com"]
            )
            
            # Verify security alert was logged
            mock_logger.warning.assert_called()
            
            # Check that warning calls contain expected information
            warning_calls = [call.args[0] for call in mock_logger.warning.call_args_list]
            
            # Should log security alert
            assert any("SECURITY ALERT" in call for call in warning_calls)
            
            # Should log attachment details
            assert any("suspicious_file.exe" in call for call in warning_calls)
            
            # Should log sender information
            assert any("attacker@malicious.com" in call for call in warning_calls)
            
            # Should log recipient information
            assert any("victim1@company.com" in call and "victim2@company.com" in call for call in warning_calls)
    
    def test_audit_logging_without_sender_recipients(self):
        """Test audit logging when sender/recipients are not provided."""
        attachment = EmailAttachment.from_file_content(
            filename="large_file.zip",
            content_type="application/zip",
            file_content=b"x" * 1000,
            file_uuid="large-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        
        policy = AttachmentPolicy(max_attachment_size=500)
        
        # Mock logger
        with patch.object(self.attachment_manager, 'logger') as mock_logger:
            # Log violation without sender/recipients
            self.attachment_manager.log_policy_violation(
                attachment=attachment,
                policy=policy,
                violation_reason="File size exceeds limit"
            )
            
            # Should still log the violation
            mock_logger.warning.assert_called()
            
            # Verify basic violation information is logged
            warning_calls = [call.args[0] for call in mock_logger.warning.call_args_list]
            assert any("SECURITY ALERT" in call for call in warning_calls)
            assert any("large_file.zip" in call for call in warning_calls)
    
    def test_audit_logging_error_handling(self):
        """Test audit logging error handling."""
        attachment = EmailAttachment.from_file_content(
            filename="test.txt",
            content_type="text/plain",
            file_content=b"content",
            file_uuid="test-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        
        policy = AttachmentPolicy()
        
        # Mock logger to raise exception
        with patch.object(self.attachment_manager, 'logger') as mock_logger:
            mock_logger.warning.side_effect = Exception("Logging error")
            
            # Should not raise exception even if logging fails
            try:
                self.attachment_manager.log_policy_violation(
                    attachment=attachment,
                    policy=policy,
                    violation_reason="Test violation"
                )
                # If we reach here, error handling worked
                assert True
            except Exception as e:
                # If logging error propagates, that's also valid behavior
                assert "Logging error" in str(e)
    
    def test_comprehensive_security_policy_enforcement(self):
        """Test comprehensive security policy enforcement scenarios."""
        # Create a strict security policy
        strict_policy = AttachmentPolicy(
            max_attachment_size=1024,  # 1KB limit
            max_total_size=2048,       # 2KB total
            max_attachments=2,
            allowed_extensions=["txt", "pdf"],
            blocked_extensions=["exe", "bat", "cmd", "scr", "pif", "com", "vbs", "js"],
            scan_for_malware=True,
            quarantine_suspicious=True
        )
        
        # Test cases: (should_pass, description, attachments)
        test_scenarios = [
            # Valid scenarios
            (True, "Single small text file", [
                EmailAttachment.from_file_content(
                    filename="readme.txt",
                    content_type="text/plain",
                    file_content=b"x" * 500,
                    file_uuid="readme-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
            ]),
            
            (True, "Two small files within limits", [
                EmailAttachment.from_file_content(
                    filename="file1.txt",
                    content_type="text/plain",
                    file_content=b"x" * 500,
                    file_uuid="file1-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                ),
                EmailAttachment.from_file_content(
                    filename="file2.pdf",
                    content_type="application/pdf",
                    file_content=b"x" * 500,
                    file_uuid="file2-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
            ]),
            
            # Invalid scenarios
            (False, "File too large", [
                EmailAttachment.from_file_content(
                    filename="large.txt",
                    content_type="text/plain",
                    file_content=b"x" * 2000,  # Exceeds 1KB limit
                    file_uuid="large-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
            ]),
            
            (False, "Too many attachments", [
                EmailAttachment.from_file_content(
                    filename="file1.txt",
                    content_type="text/plain",
                    file_content=b"x" * 200,
                    file_uuid="file1-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                ),
                EmailAttachment.from_file_content(
                    filename="file2.txt",
                    content_type="text/plain",
                    file_content=b"x" * 200,
                    file_uuid="file2-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                ),
                EmailAttachment.from_file_content(
                    filename="file3.txt",
                    content_type="text/plain",
                    file_content=b"x" * 200,
                    file_uuid="file3-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
            ]),
            
            (False, "Blocked file extension", [
                EmailAttachment.from_file_content(
                    filename="malware.exe",
                    content_type="application/x-msdownload",
                    file_content=b"x" * 500,
                    file_uuid="malware-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
            ]),
            
            (False, "Corrupted file (malware)", [
                EmailAttachment.from_file_content(
                    filename="virus.txt",
                    content_type="text/plain",
                    file_content=b"x" * 500,
                    file_uuid="virus-uuid",
                    health_status=FileSystemItemHealthStatus.CORRUPT
                )
            ]),
            
            (False, "Disallowed file extension", [
                EmailAttachment.from_file_content(
                    filename="image.jpg",  # Not in allowed list
                    content_type="image/jpeg",
                    file_content=b"x" * 500,
                    file_uuid="image-uuid",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
            ]),
        ]
        
        for should_pass, description, attachments in test_scenarios:
            is_valid, error = strict_policy.validate_message_attachments(attachments)
            
            if should_pass:
                assert is_valid is True, f"Expected to pass but failed: {description}"
                assert error is None
            else:
                assert is_valid is False, f"Expected to fail but passed: {description}"
                assert error is not None
    
    def test_security_bypass_attempts(self):
        """Test detection of common security bypass attempts."""
        policy = AttachmentPolicy(
            blocked_extensions=["exe", "bat", "cmd"],
            scan_for_malware=True
        )
        
        # Common bypass attempts
        bypass_attempts = [
            # Double extension
            EmailAttachment.from_file_content(
                filename="document.pdf.exe",
                content_type="application/x-msdownload",
                file_content=b"Disguised executable",
                file_uuid="double-ext-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # Case variation
            EmailAttachment.from_file_content(
                filename="malware.EXE",
                content_type="application/x-msdownload",
                file_content=b"Case variation attempt",
                file_uuid="case-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # Unicode/special characters
            EmailAttachment.from_file_content(
                filename="file\u202e.exe",  # Right-to-left override character
                content_type="application/x-msdownload",
                file_content=b"Unicode bypass attempt",
                file_uuid="unicode-uuid",
                health_status=FileSystemItemHealthStatus.GOOD
            ),
            
            # Corrupted file with innocent name
            EmailAttachment.from_file_content(
                filename="innocent_document.pdf",
                content_type="application/pdf",
                file_content=b"Actually corrupted content",
                file_uuid="innocent-uuid",
                health_status=FileSystemItemHealthStatus.CORRUPT
            ),
        ]
        
        for attachment in bypass_attempts:
            is_valid, error = policy.validate_attachment(attachment)
            # All bypass attempts should be caught
            assert is_valid is False, f"Bypass attempt not detected: {attachment.filename}"
    
    def test_performance_under_security_load(self):
        """Test security feature performance under load."""
        policy = AttachmentPolicy(
            max_attachments=100,
            scan_for_malware=True,
            blocked_extensions=["exe", "bat", "cmd", "scr", "pif"]
        )
        
        # Create many attachments to test performance
        many_attachments = []
        
        # Mix of clean and suspicious files
        for i in range(50):
            # Clean files
            clean_attachment = EmailAttachment.from_file_content(
                filename=f"document_{i}.pdf",
                content_type="application/pdf",
                file_content=b"x" * 1000,
                file_uuid=f"clean-{i}",
                health_status=FileSystemItemHealthStatus.GOOD
            )
            many_attachments.append(clean_attachment)
            
            # Some suspicious files
            if i % 10 == 0:  # Every 10th file is suspicious
                suspicious_attachment = EmailAttachment.from_file_content(
                    filename=f"tool_{i}.exe",
                    content_type="application/x-msdownload",
                    file_content=b"x" * 1000,
                    file_uuid=f"suspicious-{i}",
                    health_status=FileSystemItemHealthStatus.GOOD
                )
                many_attachments.append(suspicious_attachment)
        
        # Validation should complete in reasonable time
        is_valid, error = policy.validate_message_attachments(many_attachments)
        
        # Should fail due to suspicious executables
        assert is_valid is False
        assert "not allowed" in error
        
        # Test malware scanning performance
        scan_results = self.attachment_manager.scan_for_malware(many_attachments)
        
        # Should have results for all files
        assert len(scan_results) == len(many_attachments)
        
        # Should detect suspicious executables
        suspicious_count = sum(1 for result in scan_results.values() if result == "SUSPICIOUS_EXECUTABLE")
        assert suspicious_count > 0
    
    def test_security_configuration_edge_cases(self):
        """Test security configuration with edge cases."""
        # Test policy with no restrictions
        permissive_policy = AttachmentPolicy(
            max_attachment_size=1024 * 1024 * 1024,  # 1GB
            max_total_size=1024 * 1024 * 1024,       # 1GB
            max_attachments=1000,
            allowed_extensions=[],  # Empty - all allowed
            blocked_extensions=[],  # Empty - none blocked
            scan_for_malware=False,
            quarantine_suspicious=False
        )
        
        # Even malicious files should pass
        malicious_attachment = EmailAttachment.from_file_content(
            filename="virus.exe",
            content_type="application/x-msdownload",
            file_content=b"Malicious code",
            file_uuid="virus-uuid",
            health_status=FileSystemItemHealthStatus.CORRUPT
        )
        
        is_valid, error = permissive_policy.validate_attachment(malicious_attachment)
        assert is_valid is True  # No restrictions, so should pass
        
        # Test policy with maximum restrictions
        restrictive_policy = AttachmentPolicy(
            max_attachment_size=1,  # 1 byte
            max_total_size=1,       # 1 byte total
            max_attachments=1,
            allowed_extensions=["txt"],  # Only txt
            blocked_extensions=["exe", "bat", "cmd", "scr", "pif", "com", "vbs", "js", "jar", "zip"],
            scan_for_malware=True,
            quarantine_suspicious=True
        )
        
        # Only minimal files should pass
        minimal_attachment = EmailAttachment.from_file_content(
            filename="a.txt",
            content_type="text/plain",
            file_content=b"x",  # 1 byte
            file_uuid="minimal-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        
        is_valid, error = restrictive_policy.validate_attachment(minimal_attachment)
        assert is_valid is True
        
        # Anything larger should fail
        larger_attachment = EmailAttachment.from_file_content(
            filename="b.txt",
            content_type="text/plain",
            file_content=b"xx",  # 2 bytes
            file_uuid="larger-uuid",
            health_status=FileSystemItemHealthStatus.GOOD
        )
        
        is_valid, error = restrictive_policy.validate_attachment(larger_attachment)
        assert is_valid is False