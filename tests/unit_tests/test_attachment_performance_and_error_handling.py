"""
Tests for attachment performance optimizations and enhanced error handling.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from primaite.simulator.file_system.file_system import FileSystem
from primaite.simulator.file_system.file_type import FileType
from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus

from primaite_mail.simulator.network.protocols.attachment_manager import (
    AttachmentManager,
    AttachmentPolicy,
)
from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment, AttachmentPolicy

class TestAttachmentPolicyViolationLogging:
    """Test comprehensive policy violation logging."""
    
    def test_policy_violation_logging(self):
        """Test detailed policy violation logging."""
        manager = AttachmentManager()
        
        # Create test attachment and policy
        attachment = EmailAttachment(
            filename="suspicious.exe",
            content_type="application/x-msdownload",
            file_size=1000,
            file_data="dGVzdA==",
            file_uuid="test-uuid",
            health_status="CORRUPT"
        )
        
        policy = AttachmentPolicy(
            blocked_extensions=["exe"],
            scan_for_malware=True
        )
        
        # Mock logger to capture security alerts
        with patch.object(manager, 'logger') as mock_logger:
            manager.log_policy_violation(
                attachment=attachment,
                policy=policy,
                violation_reason="Malware detected",
                sender="attacker@evil.com",
                recipients=["victim@company.com"]
            )
            
            # Verify security alert was logged
            warning_calls = mock_logger.warning.call_args_list
            security_alerts = [call for call in warning_calls if "SECURITY ALERT" in call[0][0]]
            assert len(security_alerts) > 0
            
            # Verify detailed information was logged
            logged_messages = [call[0][0] for call in warning_calls]
            assert any("suspicious.exe" in msg for msg in logged_messages)
            assert any("attacker@evil.com" in msg for msg in logged_messages)
            assert any("victim@company.com" in msg for msg in logged_messages)
    
    def test_policy_violation_error_handling(self):
        """Test error handling in policy violation logging."""
        manager = AttachmentManager()
        
        # Mock logger to capture error handling
        with patch.object(manager, 'logger') as mock_logger:
            # Test logging with null attachment
            manager.log_policy_violation(
                attachment=None,
                policy=AttachmentPolicy(),
                violation_reason="Test violation"
            )
            
            # Verify error was logged appropriately
            error_calls = mock_logger.error.call_args_list
            assert len(error_calls) > 0
            assert any("null attachment" in call[0][0].lower() for call in error_calls)


class TestAttachmentMalwareScanning:
    """Test enhanced malware scanning with error handling."""
    
    def test_comprehensive_malware_scanning(self):
        """Test comprehensive malware scanning with various threat types."""
        manager = AttachmentManager()
        
        # Create test attachments with different threat levels
        attachments = [
            # Clean file
            EmailAttachment(
                filename="document.pdf",
                content_type="application/pdf",
                file_size=1000,
                file_data="dGVzdA==",
                file_uuid="clean-uuid",
                health_status="GOOD"
            ),
            # Corrupted file (malware)
            EmailAttachment(
                filename="malware.exe",
                content_type="application/x-msdownload",
                file_size=2000,
                file_data="dGVzdA==",
                file_uuid="malware-uuid",
                health_status="CORRUPT"
            ),
            # Suspicious executable
            EmailAttachment(
                filename="suspicious.bat",
                content_type="application/x-msdos-program",
                file_size=500,
                file_data="dGVzdA==",
                file_uuid="suspicious-uuid",
                health_status="GOOD"
            ),
            # Large suspicious file
            EmailAttachment(
                filename="huge_file.zip",
                content_type="application/zip",
                file_size=200 * 1024 * 1024,  # 200MB
                file_data="dGVzdA==",
                file_uuid="large-uuid",
                health_status="GOOD"
            )
        ]
        
        # Scan attachments
        scan_results = manager.scan_for_malware(attachments)
        
        # Verify scan results
        assert scan_results["document.pdf"] == "CLEAN"
        assert scan_results["malware.exe"] == "MALWARE_DETECTED"
        assert scan_results["suspicious.bat"] == "SUSPICIOUS_EXECUTABLE"  # Has both suspicious extension AND executable MIME type
        assert scan_results["huge_file.zip"] == "SUSPICIOUS_SIZE"
    
    def test_malware_scan_error_handling(self):
        """Test error handling during malware scanning."""
        manager = AttachmentManager()
        
        # Test scanning with null attachments
        attachments = [None, Mock(), None]
        
        # Mock logger to capture warnings
        with patch.object(manager, 'logger') as mock_logger:
            scan_results = manager.scan_for_malware(attachments)
            
            # Verify errors were handled gracefully
            assert len(scan_results) > 0
            assert all("SCAN_ERROR" in result for result in scan_results.values())
            
            # Verify warnings were logged
            warning_calls = mock_logger.warning.call_args_list
            assert len(warning_calls) > 0
    
    def test_double_extension_detection(self):
        """Test detection of double extension attacks."""
        manager = AttachmentManager()
        
        # Create attachment with double extension
        attachment = EmailAttachment(
            filename="document.pdf.exe",
            content_type="application/x-msdownload",
            file_size=1000,
            file_data="dGVzdA==",
            file_uuid="double-ext-uuid",
            health_status="GOOD"
        )
        
        scan_results = manager.scan_for_malware([attachment])
        
        # Should be detected as suspicious double extension
        assert scan_results["document.pdf.exe"] == "SUSPICIOUS_DOUBLE_EXTENSION"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])