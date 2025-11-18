#!/usr/bin/env python3
"""
Tests for FortiGate Rule Name Extractor
"""

import pytest
import tempfile
import os
from pathlib import Path

from fg_rule_extractor import parse_fortigate_config, extract_rule_names


class TestParseFortigateConfig:
    """Tests for the parse_fortigate_config function."""

    def test_parse_single_rule(self):
        """Test parsing a config with a single firewall rule."""
        config = """
config firewall policy
    edit 1
        set name "Test-Rule"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['id'] == '1'
        assert rules[0]['name'] == 'Test-Rule'

    def test_parse_multiple_rules(self):
        """Test parsing a config with multiple firewall rules."""
        config = """
config firewall policy
    edit 1
        set name "Rule-One"
        set srcintf "lan"
        set dstintf "wan1"
    next
    edit 2
        set name "Rule-Two"
        set srcintf "dmz"
        set dstintf "wan1"
    next
    edit 10
        set name "Rule-Ten"
        set srcintf "lan"
        set dstintf "dmz"
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 3
        assert rules[0]['id'] == '1'
        assert rules[0]['name'] == 'Rule-One'
        assert rules[1]['id'] == '2'
        assert rules[1]['name'] == 'Rule-Two'
        assert rules[2]['id'] == '10'
        assert rules[2]['name'] == 'Rule-Ten'

    def test_parse_rule_without_name(self):
        """Test parsing a rule that has no name set."""
        config = """
config firewall policy
    edit 5
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['id'] == '5'
        assert rules[0]['name'] == '<unnamed-rule-5>'

    def test_parse_mixed_named_unnamed_rules(self):
        """Test parsing rules where some have names and some don't."""
        config = """
config firewall policy
    edit 1
        set name "Named-Rule"
        set action accept
    next
    edit 2
        set action deny
    next
    edit 3
        set name "Another-Named"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 3
        assert rules[0]['name'] == 'Named-Rule'
        assert rules[1]['name'] == '<unnamed-rule-2>'
        assert rules[2]['name'] == 'Another-Named'

    def test_parse_empty_config(self):
        """Test parsing an empty configuration."""
        config = ""
        rules = parse_fortigate_config(config)
        assert len(rules) == 0

    def test_parse_config_without_firewall_policy(self):
        """Test parsing a config that has no firewall policy section."""
        config = """
config system global
    set hostname "TestFW"
end

config system interface
    edit "wan1"
        set ip 10.0.0.1 255.255.255.0
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 0

    def test_parse_rule_with_single_quotes(self):
        """Test parsing a rule name with single quotes."""
        config = """
config firewall policy
    edit 1
        set name 'Single-Quote-Rule'
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == 'Single-Quote-Rule'

    def test_parse_rule_with_spaces_in_name(self):
        """Test parsing a rule name that contains spaces."""
        config = """
config firewall policy
    edit 1
        set name "Rule With Spaces"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == 'Rule With Spaces'

    def test_parse_rule_with_special_characters(self):
        """Test parsing a rule name with special characters."""
        config = """
config firewall policy
    edit 1
        set name "Rule_With-Special.Chars#1"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == 'Rule_With-Special.Chars#1'

    def test_parse_case_insensitivity(self):
        """Test that parsing is case-insensitive for keywords."""
        config = """
CONFIG FIREWALL POLICY
    edit 1
        SET NAME "Uppercase-Config"
        set action accept
    next
END
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == 'Uppercase-Config'

    def test_parse_with_comments(self):
        """Test parsing config that includes comment fields."""
        config = """
config firewall policy
    edit 1
        set name "Rule-With-Comment"
        set action accept
        set comments "This is a test rule"
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == 'Rule-With-Comment'

    def test_parse_large_rule_id(self):
        """Test parsing a rule with a large ID number."""
        config = """
config firewall policy
    edit 99999
        set name "Large-ID-Rule"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['id'] == '99999'
        assert rules[0]['name'] == 'Large-ID-Rule'


class TestExtractRuleNames:
    """Tests for the extract_rule_names function."""

    def test_extract_from_file(self):
        """Test extracting rules from an actual file."""
        config = """
config firewall policy
    edit 1
        set name "File-Test-Rule"
        set action accept
    next
end
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config)
            temp_path = f.name

        try:
            rules = extract_rule_names(temp_path)
            assert len(rules) == 1
            assert rules[0]['name'] == 'File-Test-Rule'
        finally:
            os.unlink(temp_path)

    def test_file_not_found(self):
        """Test that FileNotFoundError is raised for missing files."""
        with pytest.raises(FileNotFoundError):
            extract_rule_names('/nonexistent/path/config.conf')

    def test_path_is_directory(self):
        """Test that ValueError is raised when path is a directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError):
                extract_rule_names(temp_dir)

    def test_extract_from_sample_config(self):
        """Test extracting rules from the sample config file if it exists."""
        sample_path = Path(__file__).parent / 'sample_fortigate.conf'
        if sample_path.exists():
            rules = extract_rule_names(str(sample_path))
            assert len(rules) == 10
            # Check first and last rules
            assert rules[0]['id'] == '1'
            assert rules[0]['name'] == 'Allow-LAN-to-Internet'
            assert rules[9]['id'] == '10'
            assert rules[9]['name'] == 'Deny-All-Default'


class TestEdgeCases:
    """Tests for edge cases and potential issues."""

    def test_empty_name(self):
        """Test parsing a rule with an empty name string."""
        config = """
config firewall policy
    edit 1
        set name ""
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == ''

    def test_multiple_firewall_policy_sections(self):
        """Test that only the first firewall policy section is parsed."""
        config = """
config firewall policy
    edit 1
        set name "First-Section-Rule"
        set action accept
    next
end

config firewall policy
    edit 2
        set name "Second-Section-Rule"
        set action accept
    next
end
"""
        rules = parse_fortigate_config(config)
        # Current implementation only finds the first section
        assert len(rules) == 1
        assert rules[0]['name'] == 'First-Section-Rule'

    def test_nested_config_blocks(self):
        """Test parsing with other nested config blocks present."""
        config = """
config system global
    set hostname "FW"
end

config firewall address
    edit "test-addr"
        set subnet 10.0.0.0 255.0.0.0
    next
end

config firewall policy
    edit 1
        set name "Test-Rule"
        set srcaddr "test-addr"
        set action accept
    next
end

config router static
    edit 1
        set gateway 10.0.0.1
    next
end
"""
        rules = parse_fortigate_config(config)
        assert len(rules) == 1
        assert rules[0]['name'] == 'Test-Rule'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
