"""Pytest configuration for PrimAITE-Mail tests."""

import pytest
from pathlib import Path
from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage


# Configure pytest markers
def pytest_configure(config):
    """Configure pytest markers for all test types."""
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end integration test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance test"
    )
    config.addinivalue_line(
        "markers", "notebook: mark test as notebook-related test"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security-focused test"
    )
    config.addinivalue_line(
        "markers", "email_protocols: mark test as email protocol test"
    )


# Test collection customization
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically based on location."""
    for item in items:
        # Add markers based on directory structure
        test_path = str(item.fspath)
        
        if "unit_tests" in test_path:
            item.add_marker(pytest.mark.unit)
        elif "integration_tests" in test_path:
            item.add_marker(pytest.mark.integration)
        elif "e2e_integration_tests" in test_path:
            item.add_marker(pytest.mark.e2e)
        elif "performance" in test_path:
            item.add_marker(pytest.mark.performance)
        
        # Add markers based on test names
        if "notebook" in item.name:
            item.add_marker(pytest.mark.notebook)
        if "security" in item.name:
            item.add_marker(pytest.mark.security)
        if "smtp" in item.name or "email" in item.name:
            item.add_marker(pytest.mark.email_protocols)


@pytest.fixture(scope="session")
def test_assets_dir() -> Path:
    """Path to test assets directory."""
    return Path(__file__).parent / "assets"


@pytest.fixture(scope="session") 
def test_output_dir() -> Path:
    """Path to test output directory."""
    output_dir = Path(__file__).parent / "test_output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


@pytest.fixture
def test_network():
    """Create a basic network for testing."""
    network = Network()
    
    # Create mail server
    mail_server = Computer.from_config({
        "type": "computer",
        "hostname": "test_mail_server",
        "ip_address": "192.168.1.10",
        "subnet_mask": "255.255.255.0",
    })
    mail_server.power_on()
    
    # Create client computer
    client_computer = Computer.from_config({
        "type": "computer",
        "hostname": "test_client",
        "ip_address": "192.168.1.20",
        "subnet_mask": "255.255.255.0",
    })
    client_computer.power_on()
    
    # Connect the computers
    network.connect(mail_server.network_interface[1], client_computer.network_interface[1])
    
    return network


@pytest.fixture
def smtp_server(test_network):
    """Create an SMTP server installed on a machine for testing."""
    mail_server = test_network.get_node_by_hostname("test_mail_server")
    mail_server.software_manager.install(SMTPServer)
    return mail_server.software_manager.software.get("smtp-server")


@pytest.fixture
def email_client(test_network):
    """Create an email client installed on a machine for testing."""
    client_computer = test_network.get_node_by_hostname("test_client")
    client_computer.software_manager.install(EmailClient)
    email_client = client_computer.software_manager.software.get("email-client")
    
    # Ensure the email client is running
    if email_client.operating_state.name != "RUNNING":
        email_client.run()
    
    return email_client


@pytest.fixture
def sample_email():
    """Create a sample email message for testing."""
    return EmailMessage(
        sender="test@example.com",
        recipients=["recipient@example.com"],
        subject="Test Email",
        body="This is a test email message."
    )


@pytest.fixture
def smtp_server_with_users(smtp_server):
    """Create an SMTP server with test users."""
    users = ["alice", "bob", "charlie"]
    for user in users:
        smtp_server.mailbox_manager.create_mailbox(user)
    return smtp_server