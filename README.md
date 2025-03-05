# YARA Rules Repository

This repository contains YARA rules for detecting malware, tracking threat actors, and identifying known good files. The rules are organized in a structured manner to facilitate easy navigation and maintenance.

## Directory Structure

```
Yara-Rules/
├── src/
│   ├── threat_groups/       # Rules for specific threat actors (APTs)
│   │   ├── APT28/
│   │   ├── APT29/
│   │   └── ...
│   ├── malware/             # Generic malware detection rules
│   │   ├── executables/
│   │   ├── documents/
│   │   ├── scripts/
│   │   └── ...
│   ├── known_good/          # Rules for benign files (goodware)
│   │   ├── operating_system/
│   │   ├── common_software/
│   │   └── ...
│   └── private/             # Private rules organized by file types
│       ├── archives/        # Rules for archive files (zip, rar, etc.)
│       ├── cad/             # Rules for CAD files
│       ├── documents/       # Rules for document files (PDF, Office, etc.)
│       ├── email/           # Rules for email files and formats
│       ├── executables/     # Rules for executable files
│       ├── fonts/           # Rules for font files
│       ├── images/          # Rules for image files
│       ├── media/           # Rules for media files (audio, video)
│       ├── vector/          # Rules for vector graphic files
│       └── virtual_disks/   # Rules for virtual disk images
```

## Naming Conventions

### File Names

- Use lowercase with underscores
- Include context such as threat group, malware family, or file type
- Examples:
  - `apt28_zebrocy_backdoor.yar`
  - `office_macro_downloader.yar`
  - `known_good_windows_dlls.yar`

### Rule Names

- Use descriptive names with underscores
- Start from broad category to specific detail
- Format: `THREATACTOR_MALWARE_ROLE_IMAGETYPE_DETAIL`
- Examples:
  - `APT28_Zebrocy_Backdoor_PE`
  - `Generic_Ransomware_Document_Macro`

## Rule Metadata Standards

Each YARA rule should include the following metadata:

```yar
rule Example_Rule {
    meta:
        description = "Detects example malware"
        author = "Your Name or Team"
        date = "YYYY-MM-DD"
        version = "1.0"
        reference = "URL or source"
        file_type = "PE"
    
    strings:
        // Rule strings here
    
    condition:
        // Rule condition here
}
```

Required metadata fields:
- `description` - What the rule detects
- `author` - Rule creator's name or handle
- `date` - Creation date (YYYY-MM-DD format)
- `version` - Rule version or revision number
- `reference` - Relevant URL or identifier for the threat

Optional metadata fields:
- `file_type` - Target file format (PE, PDF, ELF, etc.)
- `malware_family` - Name of the malware family
- `hash` - Sample hashes the rule was based on

## How to Use

To use these YARA rules, you need to have YARA installed on your system. You can then run YARA against files or directories:

```bash
# Scan a single file with a specific rule
yara rule.yar file_to_scan

# Scan a directory recursively with all rules
yara -r rules_directory/ directory_to_scan
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
