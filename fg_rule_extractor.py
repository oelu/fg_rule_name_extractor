#!/usr/bin/env python3
"""
FortiGate 7.2.x Configuration Parser
Extracts firewall rule names from FortiGate configuration files.
"""

import re
import argparse
import sys
from pathlib import Path


def parse_fortigate_config(config_content: str) -> list[dict]:
    """
    Parse FortiGate configuration and extract firewall rule information.

    Args:
        config_content: The full text content of the FortiGate config file

    Returns:
        List of dictionaries containing rule id and name
    """
    rules = []

    # Pattern to match firewall policy sections
    # FortiGate config structure:
    # config firewall policy
    #     edit <id>
    #         set name "rule_name"
    #         ...
    #     next
    # end

    # Find the firewall policy config block
    policy_pattern = re.compile(
        r'config firewall policy\s*(.*?)\s*end',
        re.DOTALL | re.IGNORECASE
    )

    policy_match = policy_pattern.search(config_content)

    if not policy_match:
        return rules

    policy_block = policy_match.group(1)

    # Find each rule within the policy block
    # Each rule starts with "edit <id>" and ends with "next"
    rule_pattern = re.compile(
        r'edit\s+(\d+)\s*(.*?)\s*next',
        re.DOTALL
    )

    for rule_match in rule_pattern.finditer(policy_block):
        rule_id = rule_match.group(1)
        rule_content = rule_match.group(2)

        # Extract the rule name
        # Format: set name "rule_name" or set name 'rule_name'
        name_pattern = re.compile(
            r'set\s+name\s+["\']([^"\']*)["\']',
            re.IGNORECASE
        )

        name_match = name_pattern.search(rule_content)

        if name_match:
            rule_name = name_match.group(1)
        else:
            rule_name = f"<unnamed-rule-{rule_id}>"

        rules.append({
            'id': rule_id,
            'name': rule_name
        })

    return rules


def extract_rule_names(config_path: str) -> list[dict]:
    """
    Read a FortiGate config file and extract rule names.

    Args:
        config_path: Path to the FortiGate configuration file

    Returns:
        List of dictionaries containing rule id and name
    """
    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {config_path}")

    # Read the config file
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        config_content = f.read()

    return parse_fortigate_config(config_content)


def main():
    parser = argparse.ArgumentParser(
        description='Extract firewall rule names from FortiGate 7.2.x configuration files'
    )
    parser.add_argument(
        'config_file',
        help='Path to the FortiGate configuration file'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: stdout)',
        default=None
    )
    parser.add_argument(
        '--format',
        choices=['simple', 'detailed', 'csv'],
        default='detailed',
        help='Output format (default: detailed)'
    )

    args = parser.parse_args()

    try:
        rules = extract_rule_names(args.config_file)

        if not rules:
            print("No firewall rules found in the configuration file.", file=sys.stderr)
            sys.exit(1)

        # Format output
        output_lines = []

        if args.format == 'simple':
            output_lines = [rule['name'] for rule in rules]
        elif args.format == 'detailed':
            output_lines.append(f"Found {len(rules)} firewall rule(s):\n")
            for rule in rules:
                output_lines.append(f"  ID: {rule['id']:>6}  |  Name: {rule['name']}")
        elif args.format == 'csv':
            output_lines.append("id,name")
            for rule in rules:
                # Escape quotes in CSV
                name = rule['name'].replace('"', '""')
                output_lines.append(f'{rule["id"]},"{name}"')

        output = '\n'.join(output_lines)

        # Write output
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output + '\n')
            print(f"Output written to: {args.output}")
        else:
            print(output)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error processing configuration: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
