import os
import requests
import json
from file_type import FileTypeAnalyzer
from yara_scan import MalwareScanner

url = os.environ["TARGET_URL"]
filename = os.environ["FILENAME"]
path = f"downloads/{filename}"

res = requests.get(url)
with open(path, "wb") as f:
    f.write(res.content)

file_info = FileTypeAnalyzer().analyze_file(path)
scan_info = MalwareScanner().scan_file(path)

result = {
    "filename": filename,
    "file_type": file_info.get("signature_type"),
    "is_malicious": scan_info.get("is_malicious"),
    "yara_matches": scan_info.get("yara_matches"),
    "risk_score": scan_info.get("risk_score"),
    "message": "악성 파일입니다." if scan_info.get("is_malicious") else "안전한 파일입니다."
}

print("<RESULT>")
print(json.dumps(result))
