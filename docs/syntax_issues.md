# YARA Syntax Error Examples

Below are 50 YARA rules containing various syntax mistakes followed by corrected versions.

## 1. Missing closing quote in string

**Broken**
```yara
rule missing_quote {
    strings:
        $a = "malware
    condition:
        $a
}
```

**Fix**
```yara
rule missing_quote {
    strings:
        $a = "malware"
    condition:
        $a
}
```

## 2. Missing closing brace

**Broken**
```yara
rule missing_brace {
    strings:
        $a = "test"
    condition:
        $a

```

**Fix**
```yara
rule missing_brace {
    strings:
        $a = "test"
    condition:
        $a
}
```

## 3. Using '=' instead of ':' after strings

**Broken**
```yara
rule wrong_strings_delim {
    strings=
        $a = "foo"
    condition:
        $a
}
```

**Fix**
```yara
rule wrong_strings_delim {
    strings:
        $a = "foo"
    condition:
        $a
}
```

## 4. Missing condition section

**Broken**
```yara
rule no_condition {
    strings:
        $a = "abc"
}
```

**Fix**
```yara
rule no_condition {
    strings:
        $a = "abc"
    condition:
        $a
}
```

## 5. Undefined string in condition

**Broken**
```yara
rule undefined_string {
    strings:
        $a = "abc"
    condition:
        $b
}
```

**Fix**
```yara
rule undefined_string {
    strings:
        $a = "abc"
    condition:
        $a
}
```

## 6. Duplicate string identifier

**Broken**
```yara
rule duplicate_id {
    strings:
        $a = "one"
        $a = "two"
    condition:
        any of them
}
```

**Fix**
```yara
rule duplicate_id {
    strings:
        $a1 = "one"
        $a2 = "two"
    condition:
        any of them
}
```

## 7. Invalid character in hex string

**Broken**
```yara
rule bad_hex_char {
    strings:
        $a = { 4G 5A }
    condition:
        $a
}
```

**Fix**
```yara
rule bad_hex_char {
    strings:
        $a = { 4F 5A }
    condition:
        $a
}
```

## 8. Hex string with odd number of digits

**Broken**
```yara
rule odd_hex_digits {
    strings:
        $a = { 41 4 }
    condition:
        $a
}
```

**Fix**
```yara
rule odd_hex_digits {
    strings:
        $a = { 41 04 }
    condition:
        $a
}
```

## 9. Rule name with space

**Broken**
```yara
rule bad name {
    strings:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule bad_name {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 10. Rule name starting with a digit

**Broken**
```yara
rule 1badname {
    strings:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule badname1 {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 11. Missing 'rule' keyword

**Broken**
```yara
missing_keyword {
    strings:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule missing_keyword {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 12. Using reserved word as string identifier

**Broken**
```yara
rule reserved_identifier {
    strings:
        condition = "x"
    condition:
        condition
}
```

**Fix**
```yara
rule reserved_identifier {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 13. Missing colon after meta

**Broken**
```yara
rule meta_no_colon {
    meta
        author = "me"
    strings:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule meta_no_colon {
    meta:
        author = "me"
    strings:
        $a = "x"
    condition:
        $a
}
```

## 14. Using '=' in meta key

**Broken**
```yara
rule bad_meta_assignment {
    meta:
        author=="me"
    strings:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule bad_meta_assignment {
    meta:
        author = "me"
    strings:
        $a = "x"
    condition:
        $a
}
```

## 15. Trailing comma in strings section

**Broken**
```yara
rule trailing_comma {
    strings:
        $a = "one",
    condition:
        $a
}
```

**Fix**
```yara
rule trailing_comma {
    strings:
        $a = "one"
    condition:
        $a
}
```

## 16. Unclosed comment

**Broken**
```yara
rule unclosed_comment {
    strings:
        $a = "x" /* comment
    condition:
        $a
}
```

**Fix**
```yara
rule unclosed_comment {
    strings:
        $a = "x" /* comment */
    condition:
        $a
}
```

## 17. Using single quotes for string

**Broken**
```yara
rule single_quote_string {
    strings:
        $a = 'test'
    condition:
        $a
}
```

**Fix**
```yara
rule single_quote_string {
    strings:
        $a = "test"
    condition:
        $a
}
```

## 18. Regex missing closing slash

**Broken**
```yara
rule regex_unclosed {
    strings:
        $a = /abc
    condition:
        $a
}
```

**Fix**
```yara
rule regex_unclosed {
    strings:
        $a = /abc/
    condition:
        $a
}
```

## 19. Using '=' instead of '==' in condition

**Broken**
```yara
rule single_equals_condition {
    strings:
        $a = "x"
    condition:
        filesize = 10
}
```

**Fix**
```yara
rule single_equals_condition {
    strings:
        $a = "x"
    condition:
        filesize == 10
}
```

## 20. Mismatched parentheses

**Broken**
```yara
rule paren_mismatch {
    strings:
        $a = "x"
    condition:
        ($a
}
```

**Fix**
```yara
rule paren_mismatch {
    strings:
        $a = "x"
    condition:
        ($a)
}
```

## 21. Condition references undefined variable

**Broken**
```yara
rule undefined_variable {
    strings:
        $a = "x"
    condition:
        b
}
```

**Fix**
```yara
rule undefined_variable {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 22. 'nocase' outside string options

**Broken**
```yara
rule nocase_outside {
    strings:
        $a = "x"
    condition:
        $a nocase
}
```

**Fix**
```yara
rule nocase_outside {
    strings:
        $a = "x" nocase
    condition:
        $a
}
```

## 23. Missing '$' in condition

**Broken**
```yara
rule missing_dollar {
    strings:
        $a = "x"
    condition:
        a
}
```

**Fix**
```yara
rule missing_dollar {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 24. 'strings' section misspelled

**Broken**
```yara
rule strings_misspelled {
    string:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule strings_misspelled {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 25. Duplicate rule name

**Broken**
```yara
rule dup_rule {
    strings:
        $a = "x"
    condition:
        $a
}

rule dup_rule {
    strings:
        $b = "y"
    condition:
        $b
}
```

**Fix**
```yara
rule dup_rule_first {
    strings:
        $a = "x"
    condition:
        $a
}

rule dup_rule_second {
    strings:
        $b = "y"
    condition:
        $b
}
```

## 26. Condition not boolean

**Broken**
```yara
rule condition_not_boolean {
    strings:
        $a = "x"
    condition:
        5
}
```

**Fix**
```yara
rule condition_not_boolean {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 27. Incorrect wildcard reference

**Broken**
```yara
rule bad_wildcard_ref {
    strings:
        $a1 = "x"
        $a2 = "y"
    condition:
        any of ($a*)
}
```

**Fix**
```yara
rule bad_wildcard_ref {
    strings:
        $a1 = "x"
        $a2 = "y"
    condition:
        any of ($a1,$a2)
}
```

## 28. Wrong comment style

**Broken**
```yara
rule wrong_comment {
    strings:
        $a = "x" // comment /*
    condition:
        $a
}
```

**Fix**
```yara
rule wrong_comment {
    strings:
        $a = "x" // comment
    condition:
        $a
}
```

## 29. Incorrect hex jump syntax

**Broken**
```yara
rule bad_jump {
    strings:
        $a = { 41 [ 5 ] 42 }
    condition:
        $a
}
```

**Fix**
```yara
rule bad_jump {
    strings:
        $a = { 41 [5] 42 }
    condition:
        $a
}
```

## 30. meta section outside braces

**Broken**
```yara
meta:
    author = "me"
rule meta_outside {
    strings:
        $a = "x"
    condition:
        $a
}
```

**Fix**
```yara
rule meta_outside {
    meta:
        author = "me"
    strings:
        $a = "x"
    condition:
        $a
}
```

## 31. Import without quotes

**Broken**
```yara
import pe
rule missing_import_quotes {
    condition:
        true
}
```

**Fix**
```yara
import "pe"
rule missing_import_quotes {
    condition:
        true
}
```

## 32. Extra text after 'private rule'

**Broken**
```yara
private rule extra text {
    condition:
        true
}
```

**Fix**
```yara
private rule extra_text {
    condition:
        true
}
```

## 33. Incorrect tag separator

**Broken**
```yara
rule tag_separator ,tag1 {
    condition:
        true
}
```

**Fix**
```yara
rule tag_separator : tag1 {
    condition:
        true
}
```

## 34. Filesize used without condition

**Broken**
```yara
rule filesize_no_condition {
    strings:
        $a = "x"
    condition:
        filesize
}
```

**Fix**
```yara
rule filesize_no_condition {
    strings:
        $a = "x"
    condition:
        filesize > 0
}
```

## 35. Missing module import for PE

**Broken**
```yara
rule pe_without_import {
    condition:
        pe.is_pe
}
```

**Fix**
```yara
import "pe"
rule pe_without_import {
    condition:
        pe.is_pe
}
```

## 36. Misspelled string modifier

**Broken**
```yara
rule misspelled_modifier {
    strings:
        $a = "x" full-word
    condition:
        $a
}
```

**Fix**
```yara
rule misspelled_modifier {
    strings:
        $a = "x" fullword
    condition:
        $a
}
```

## 37. Hyphen in string identifier

**Broken**
```yara
rule hyphen_identifier {
    strings:
        $a-1 = "x"
    condition:
        $a-1
}
```

**Fix**
```yara
rule hyphen_identifier {
    strings:
        $a1 = "x"
    condition:
        $a1
}
```

## 38. 'any of them' with no strings

**Broken**
```yara
rule any_of_none {
    condition:
        any of them
}
```

**Fix**
```yara
rule any_of_none {
    strings:
        $a = "x"
    condition:
        any of them
}
```

## 39. '2 of ($a*)' with missing strings

**Broken**
```yara
rule two_of_missing {
    strings:
        $b1 = "x"
    condition:
        2 of ($a*)
}
```

**Fix**
```yara
rule two_of_missing {
    strings:
        $a1 = "x"
        $a2 = "y"
    condition:
        2 of ($a*)
}
```

## 40. Using '@' on undefined string

**Broken**
```yara
rule at_undefined {
    condition:
        @a
}
```

**Fix**
```yara
rule at_undefined {
    strings:
        $a = "x"
    condition:
        @a
}
```

## 41. Invalid hex number

**Broken**
```yara
rule invalid_hex_number {
    condition:
        0xZZ == 5
}
```

**Fix**
```yara
rule invalid_hex_number {
    condition:
        0x2A == 42
}
```

## 42. Using 'entrypoint' without PE import

**Broken**
```yara
rule entrypoint_no_import {
    condition:
        pe.entry_point == 0
}
```

**Fix**
```yara
import "pe"
rule entrypoint_no_import {
    condition:
        pe.entry_point == 0
}
```

## 43. Invalid function call

**Broken**
```yara
rule invalid_function {
    condition:
        nonexistent_function()
}
```

**Fix**
```yara
rule invalid_function {
    condition:
        true
}
```

## 44. Strings defined after condition

**Broken**
```yara
rule strings_after_condition {
    condition:
        $a
    strings:
        $a = "x"
}
```

**Fix**
```yara
rule strings_after_condition {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 45. Missing braces

**Broken**
```yara
rule no_braces
    strings:
        $a = "x"
    condition:
        $a
```

**Fix**
```yara
rule no_braces {
    strings:
        $a = "x"
    condition:
        $a
}
```

## 46. Using 'include' instead of 'import'

**Broken**
```yara
include "pe"
rule wrong_include {
    condition:
        true
}
```

**Fix**
```yara
import "pe"
rule wrong_include {
    condition:
        true
}
```

## 47. Incorrect 'not' usage

**Broken**
```yara
rule wrong_not {
    strings:
        $a = "x"
    condition:
        not
}
```

**Fix**
```yara
rule wrong_not {
    strings:
        $a = "x"
    condition:
        not $a
}
```

## 48. Using undefined module variable

**Broken**
```yara
rule undefined_module_var {
    condition:
        mymodule.value == 1
}
```

**Fix**
```yara
import "mymodule"
rule undefined_module_var {
    condition:
        mymodule.value == 1
}
```

## 49. Tags separated by commas

**Broken**
```yara
rule tags_with_commas : tag1, tag2 {
    condition:
        true
}
```

**Fix**
```yara
rule tags_with_commas : tag1 tag2 {
    condition:
        true
}
```

## 50. Incorrect case for keyword

**Broken**
```yara
Rule uppercase_keyword {
    strings:
        $a = "x"
    Condition:
        $a
}
```

**Fix**
```yara
rule uppercase_keyword {
    strings:
        $a = "x"
    condition:
        $a
}
```

