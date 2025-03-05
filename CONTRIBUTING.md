# Contributing to YARA Rules Repository

Thank you for your interest in contributing to our YARA rules repository! This document provides guidelines and instructions for contributing.

## How to Contribute

1. Fork the repository
2. Create a new branch for your contribution
3. Add or modify YARA rules following the guidelines below
4. Test your rules against both malicious and benign samples
5. Submit a pull request

## Rule Development Guidelines

### Directory Structure

Place your rules in the appropriate directory based on their purpose:

- `src/threat_groups/` - For rules targeting specific threat actors
- `src/malware/` - For generic malware detection rules
- `src/known_good/` - For rules identifying benign files
- `src/private/` - For private or organization-specific rules

### File Naming

- Use lowercase with underscores
- Include context such as threat group, malware family, or file type
- Examples:
  - `apt28_zebrocy_backdoor.yar`
  - `office_macro_downloader.yar`

### Rule Naming

- Use descriptive names with underscores
- Start from broad category to specific detail
- Format: `THREATACTOR_MALWARE_ROLE_IMAGETYPE_DETAIL`
- Examples:
  - `APT28_Zebrocy_Backdoor_PE`
  - `Generic_Ransomware_Document_Macro`

### Metadata Requirements

Each rule must include the following metadata:

```yar
meta:
    description = "Detects example malware"
    author = "Your Name or Team"
    date = "YYYY-MM-DD"
    version = "1.0"
    reference = "URL or source"
```

Additional metadata fields are encouraged:
- `file_type` - Target file format (PE, PDF, ELF, etc.)
- `malware_family` - Name of the malware family
- `hash` - Sample hashes the rule was based on

### Code Style

- Use consistent indentation (4 spaces recommended)
- Add comments for complex conditions or non-obvious strings
- Use meaningful variable names for YARA rule identifiers
- Group related strings together
- Use modifiers appropriately (e.g., `nocase`, `wide`, `ascii`)

### Testing

Before submitting a pull request:

1. Test your rules against known malicious samples they should detect
2. Test against benign samples to check for false positives
3. Verify syntax using `yarac` (YARA compiler)
4. Document any dependencies (e.g., if your rule requires the `pe` module)

## Pull Request Process

1. Ensure your rules follow all the guidelines above
2. Provide a clear description of what your rules detect
3. Include information about testing performed
4. Link to any relevant research or references
5. Be responsive to feedback and be prepared to make changes if requested

## Code of Conduct

- Be respectful and constructive in discussions
- Provide helpful feedback on others' contributions
- Focus on the technical merits of rules and suggestions
- Maintain a collaborative and inclusive environment

Thank you for contributing to making our YARA rules repository more effective and comprehensive!
