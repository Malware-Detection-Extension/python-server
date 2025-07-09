from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import os
from analyzer.file_type import get_file_type
from analyzer.yara_scan import scan_with_yara
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

@app.route("/report_download", methods=["POST"])
def report_download():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload received"}), 400

    url = data.get("url")
    raw_filename = data.get("filename", "")

    if not raw_filename or raw_filename.strip() == "" or raw_filename == "unknown_file":
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or "downloaded.bin"
    else:
        filename = os.path.basename(raw_filename)

    filepath = os.path.join(DOWNLOAD_DIR, filename)

    try:
        print(f"\n[+] 다운로드 URL: {url}")
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        with open(filepath, "wb") as f:
            f.write(response.content)
        print(f"[+] 다운로드 완료: {filepath}")

        file_type = get_file_type(filepath)
        yara_matches = scan_with_yara(filepath)

        print(f"[+] 파일 유형: {file_type}")
        print(f"[+] YARA 매치: {yara_matches}")

        return jsonify({
            "filename": filename,
            "file_type": file_type,
            "is_malicious": bool(yara_matches),
            "yara_matches": yara_matches
        }), 200

    except requests.exceptions.RequestException as re:
        print("[!] 다운로드 실패:", re)
        return jsonify({"error": f"Download error: {str(re)}"}), 500
    except Exception as e:
        print("[!] 처리 중 예외 발생:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/safe_download/<filename>", methods=["GET"])
def safe_download(filename):
    safe_path = os.path.join(DOWNLOAD_DIR, filename)
    if not os.path.exists(safe_path):
        return "File not found", 404
    return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
