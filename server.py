# server.py

import os
import json
import logging
import hashlib
import uuid
import base64
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
from controller import launch_worker_container

app = Flask(__name__)
CORS(app)

REPORTS_DIR = "reports"
QUARANTINE_DIR = "quarantine"
DOWNLOAD_DIR = "downloads"

for d in [REPORTS_DIR, QUARANTINE_DIR, DOWNLOAD_DIR]:
    os.makedirs(d, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")

def get_unique_filename(filename):
    # 예: 20240720_145932_95de28f1ec.file.exe
    base = datetime.now().strftime('%Y%m%d_%H%M%S')
    rand = uuid.uuid4().hex[:10]
    sanitized = os.path.basename(filename)
    return f"{base}_{rand}.{sanitized}"

@app.route("/")
def serve_index():
    logger.info("[*] Serving index.html")
    return send_from_directory('.', 'index.html')

@app.route("/report_download", methods=["POST"])
def report_download():
    try:
        data = request.get_json()
        url = data.get("url")
        raw_filename = data.get("filename") or "download.bin"
        safe_filename = get_unique_filename(raw_filename)
        #print(f"data>\n{data}\n\nurl>\n{url}\n\nraw_filename>\n{raw_filename}\n\nsafe_filename>\n{safe_filename}\n")

        #logger.info(f"[*] Request analysis: {url}, filename: {safe_filename}")

        result = launch_worker_container(url, safe_filename)
        logger.info(f"[+] Analysis done: {result}")

        # 악성일 경우 격리로그 작성
        if result.get("is_malicious"):
            try:
                quarantine_log = {
                    "timestamp": datetime.now().isoformat(),
                    "filename": safe_filename,
                    "reason": result.get("message")
                }
                with open(os.path.join(QUARANTINE_DIR, "quarantine.log"), "a") as f:
                    f.write(json.dumps(quarantine_log) + "\n")
            except Exception as e:
                logger.warning(f"[!] Failed to save quarantine log: {e}")

        # 결과 리포트 저장
        try:
            report_path = os.path.join(REPORTS_DIR, f"report_{safe_filename}.json")
            with open(report_path, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"[+] Saved report: {report_path}")
        except Exception as e:
            logger.error(f"[!] Failed to save report: {e}")

        # 안전한 파일명 응답에 추가
        if not result.get("is_malicious"):
            result["safe_filename"] = safe_filename

        return jsonify(result), 200

    except Exception as e:
        logger.exception("[!] Error in report_download")
        return jsonify({"error": str(e)}), 500

@app.route("/safe_download/<filename>")
def safe_download(filename):
    if not filename or ".." in filename:
        return jsonify({"error": "Invalid filename"}), 400
    filepath = os.path.join(DOWNLOAD_DIR, filename)
    if not os.path.exists(filepath):
        logger.warning(f"[!] File not found: {filepath}")
        return jsonify({"error": "File not found"}), 404
    return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
