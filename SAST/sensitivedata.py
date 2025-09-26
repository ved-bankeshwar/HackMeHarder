import re
import math
import json
import os
import yaml 

def load_rules(rules_filepath): #-->separating mind and body, any changes can be made directly to yoml file which makes it dynamic
    """Loads scanner rules from a YAML file."""
    try:
        with open(rules_filepath, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading rules file {rules_filepath}: {e}")
        return []
    
#Helper Functions

#randomness zyada matlab it could be a password/key string - using weighted probability of surprise
def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for char_code in range(256):
        prob = float(text.count(chr(char_code))) / len(text)
        if prob > 0:
            entropy += -prob * math.log(prob, 2)
    return entropy

def extract_strings_from_line(line):
    return re.findall(r'["\'](.*?)["\']', line)

# The Optimized Single-Pass Scanner 
def scan_file_for_secrets(filepath,rules):
    findings = []

    # Pre-compile regexes once for performance
    compiled_rules = [
        (re.compile(rule["regex"]), rule) for rule in rules
    ]

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Step 2: Iterate through each line of the file once
            for line_num, line in enumerate(f, 1):
                line_has_regex_match = False

                # Step 3: Check against high-confidence regexes first
                for pattern, rule in compiled_rules:
                    match = pattern.search(line)
                    if match:
                        matched_value = match.group(0)
                        findings.append({
                            "type": "SAST-Secret",
                            "rule_id": rule["id"],
                            "description": rule["description"],
                            "file": filepath,
                            "line": line_num,
                            "severity": rule["severity"],
                            "match_type": "Regex",
                            "matched_value": matched_value 
                        })
                        line_has_regex_match = True
                        break  # Stop checking other regexes for this line

                # If a regex matched, short-circuit and move to the next line
                if line_has_regex_match:
                    continue

                # Step 4: Conditional Entropy Fallback (only if no regex matched)
                strings = extract_strings_from_line(line)
                for s in strings:
                    # Pre-filter to avoid checking every small or simple string
                    if len(s) >= 20:
                        entropy = calculate_entropy(s)
                        if entropy > 4.5:
                            findings.append({
                                "type": "SAST-Secret",
                                "rule_id": "high-entropy-string",
                                "description": "Potential secret found due to high entropy",
                                "file": filepath,
                                "line": line_num,
                                "severity": "Medium",
                                "match_type": "Entropy",
                                "matched_value": s, 
                                "entropy_score": round(entropy, 2)
                            })
                            break
    except Exception as e:
        print(f"Error scanning file {filepath}: {e}")

    return findings
