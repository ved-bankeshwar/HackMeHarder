import re
import math
import yaml 

def load_rules(rules_filepath): 
    try:
        with open(rules_filepath, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading rules file {rules_filepath}: {e}")
        return []
    
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

 
def scan_file_for_secrets(filepath,rules):
    findings = []

    compiled_rules = [
        (re.compile(rule["regex"]), rule) for rule in rules
    ]

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
        
            for line_num, line in enumerate(f, 1):
                line_has_regex_match = False

                
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
                        break  

                
                if line_has_regex_match:
                    continue

                
                strings = extract_strings_from_line(line)
                for s in strings:
                    
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

