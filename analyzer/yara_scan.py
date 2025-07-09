import yara

RULE_PATH = "analyzer/rules.yar"

def scan_with_yara(file_path):
    try:
        rules = yara.compile(filepath=RULE_PATH)
        matches = rules.match(file_path)
        return [match.rule for match in matches]
    except Exception as e:
        return [f"Error: {str(e)}"]
