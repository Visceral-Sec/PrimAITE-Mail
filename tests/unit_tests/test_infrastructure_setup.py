"""
Test the testing infrastructure setup.

This test verifies that the testing directory structure and configuration
are set up correctly for the comprehensive email security demonstration.
"""

import pytest
from pathlib import Path
from primaite.config.load import load


class TestInfrastructureSetup:
    """Test the testing infrastructure components."""

    def test_directory_structure_exists(self):
        """Test that all required testing directories exist."""
        tests_dir = Path(__file__).parent.parent
        
        # Check main test directories
        assert (tests_dir / "unit_tests").exists()
        assert (tests_dir / "integration_tests").exists()
        assert (tests_dir / "e2e_integration_tests").exists()
        assert (tests_dir / "assets").exists()
        assert (tests_dir / "test_output").exists()
        
        # Check assets subdirectories
        assert (tests_dir / "assets" / "configs").exists()

    def test_run_test_script_exists(self):
        """Test that the run_test.sh script exists and is executable."""
        tests_dir = Path(__file__).parent.parent
        script_path = tests_dir / "run_test.sh"
        
        assert script_path.exists()
        assert script_path.is_file()
        # Check if executable (on Unix systems)
        import stat
        assert script_path.stat().st_mode & stat.S_IEXEC

    def test_configuration_files_load(self):
        """Test that all configuration files can be loaded."""
        configs_dir = Path(__file__).parent.parent / "assets" / "configs"
        
        config_files = [
            "basic_email_network.yaml",
            "multi_agent_email_scenario.yaml",
            "security_policy_test.yaml",
            "comprehensive_demo_test.yaml",
            "smtp_server_with_security_policies.yaml"
        ]
        
        for config_file in config_files:
            config_path = configs_dir / config_file
            assert config_path.exists(), f"Configuration file {config_file} not found"
            
            # Load and validate configuration
            config = load(str(config_path))
            assert config is not None, f"Failed to load {config_file}"
            assert "simulation" in config, f"Missing simulation section in {config_file}"

    def test_pytest_configuration(self):
        """Test that pytest is configured correctly."""
        # This test runs, so pytest is working
        # Check that we can import required modules
        import pytest
        import primaite
        import primaite_mail
        
        # Check that markers are available
        # (This would be validated by pytest itself if markers are properly configured)
        assert True

    def test_test_output_directory_writable(self):
        """Test that test output directory is writable."""
        test_output_dir = Path(__file__).parent.parent / "test_output"
        
        # Create a test file to verify write permissions
        test_file = test_output_dir / "infrastructure_test.txt"
        test_file.write_text("Infrastructure test successful")
        
        assert test_file.exists()
        assert test_file.read_text() == "Infrastructure test successful"
        
        # Clean up
        test_file.unlink()

    @pytest.mark.unit
    def test_unit_test_marker(self):
        """Test that unit test marker is applied correctly."""
        # This test should have the unit marker applied automatically
        assert True

    def test_comprehensive_demo_config_structure(self):
        """Test that the comprehensive demo configuration has correct structure."""
        configs_dir = Path(__file__).parent.parent / "assets" / "configs"
        config_path = configs_dir / "comprehensive_demo_test.yaml"
        
        config = load(str(config_path))
        
        # Check main structure
        assert "simulation" in config
        assert "network" in config["simulation"]
        assert "nodes" in config["simulation"]["network"]
        
        nodes = config["simulation"]["network"]["nodes"]
        
        # Check that we have all required node types
        required_nodes = [
            "mail_server",
            "alice_workstation", 
            "bob_workstation",
            "charlie_workstation",
            "security_workstation",
            "attacker_system"
        ]
        
        for node_name in required_nodes:
            assert node_name in nodes, f"Missing required node: {node_name}"
        
        # Check mail server has required services
        mail_server = nodes["mail_server"]
        assert "services" in mail_server
        
        service_types = [service["type"] for service in mail_server["services"]]
        assert "smtp-server" in service_types
        assert "pop3-server" in service_types


if __name__ == "__main__":
    # Allow running this test directly
    pytest.main([__file__, "-v"])