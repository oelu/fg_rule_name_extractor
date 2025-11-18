# FortiGate Rule Name Extractor

A Python script that parses FortiGate 7.2.x configuration files and extracts firewall rule names.

## Requirements

- Python 3.9+
- No external dependencies

## Installation

```bash
git clone <repository-url>
cd fg_rule_name_extractor
```

## Usage

```bash
# Basic usage - displays rules with IDs
python fg_rule_extractor.py /path/to/fortigate.conf

# Simple output - just rule names, one per line
python fg_rule_extractor.py --format simple /path/to/fortigate.conf

# CSV output
python fg_rule_extractor.py --format csv /path/to/fortigate.conf

# Save output to file
python fg_rule_extractor.py -o rules.txt /path/to/fortigate.conf
```

## Output Formats

| Format | Description |
|--------|-------------|
| `detailed` | (default) Shows rule count, IDs, and names |
| `simple` | Rule names only, one per line |
| `csv` | CSV format with id and name columns |

## Example

```bash
$ python fg_rule_extractor.py sample_fortigate.conf

Found 10 firewall rule(s):

  ID:      1  |  Name: Allow-LAN-to-Internet
  ID:      2  |  Name: Allow-LAN-to-DMZ
  ID:      3  |  Name: DMZ-Web-Server-Inbound
  ...
```

## Testing

### Run the test suite

```bash
# Install pytest (if not already installed)
pip install pytest

# Run all tests
pytest test_fg_rule_extractor.py -v

# Run specific test class
pytest test_fg_rule_extractor.py::TestParseFortigateConfig -v
```

### Manual testing

A sample configuration file is included:

```bash
python fg_rule_extractor.py sample_fortigate.conf
```

## Test Coverage

The test suite covers:
- Single and multiple rule parsing
- Named and unnamed rules
- Special characters and spaces in names
- Empty configs and missing policy sections
- File handling errors
- Edge cases (empty names, large IDs, nested configs)
