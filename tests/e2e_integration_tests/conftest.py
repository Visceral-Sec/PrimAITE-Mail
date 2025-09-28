"""
Pytest configuration and fixtures for end-to-end integration tests.

Provides common fixtures and setup for comprehensive email security demonstration tests.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Generator

# Import PrimAITE components following correct patterns
from primaite.config.load import load


@pytest.fixture(scope="session")
def test_assets_dir() -> Path:
    """Path to test assets directory."""
    return Path(__file__).parent.parent / "assets"


@pytest.fixture(scope="session")
def test_configs_dir(test_assets_dir: Path) -> Path:
    """Path to test configuration files."""
    return test_assets_dir / "configs"


@pytest.fixture(scope="session")
def test_output_dir() -> Path:
    """Path to test output directory."""
    output_dir = Path(__file__).parent.parent / "test_output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


@pytest.fixture
def temp_output_dir() -> Generator[Path, None, None]:
    """Temporary directory for test outputs that gets cleaned up."""
    temp_dir = Path(tempfile.mkdtemp(prefix="primaite_mail_test_"))
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def basic_email_config(test_configs_dir: Path) -> Dict[str, Any]:
    """Load basic email network configuration."""
    config_path = test_configs_dir / "basic_email_network.yaml"
    return load(str(config_path))


@pytest.fixture
def multi_agent_config(test_configs_dir: Path) -> Dict[str, Any]:
    """Load multi-agent scenario configuration."""
    config_path = test_configs_dir / "multi_agent_email_scenario.yaml"
    return load(str(config_path))


@pytest.fixture
def security_policy_config(test_configs_dir: Path) -> Dict[str, Any]:
    """Load security policy test configuration."""
    config_path = test_configs_dir / "security_policy_test.yaml"
    return load(str(config_path))


@pytest.fixture
def smtp_security_config(test_configs_dir: Path) -> Dict[str, Any]:
    """Load SMTP server with security policies configuration."""
    config_path = test_configs_dir / "smtp_server_with_security_policies.yaml"
    return load(str(config_path))


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up test environment before each test."""
    # This fixture runs automatically before each test
    # Can be used to set up common test state
    
    # Ensure test output directory exists
    test_output = Path(__file__).parent.parent / "test_output"
    test_output.mkdir(exist_ok=True)
    
    yield
    
    # Cleanup after test if needed
    pass


# Markers for different test categories
def pytest_configure(config):
    """Configure pytest markers."""
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


# Test collection customization
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add e2e marker to all tests in e2e_integration_tests directory
        if "e2e_integration_tests" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        
        # Add performance marker to performance tests
        if "performance" in item.name or "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
        
        # Add notebook marker to notebook-related tests
        if "notebook" in item.name:
            item.add_marker(pytest.mark.notebook)
        
        # Add security marker to security-related tests
        if "security" in item.name or "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)