# worker/app.py

import os
import re
import base64
import requests
import json
import logging
import sys

from file_type import FileTypeAnalyzer
from yara_scan import MalwareScanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stderr)
logger = logging.getLogger("worker_app")

DOWNLOADS_DIR = "/app/downloads"
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

def main():
    result_to_output = {
        "filename": None,
        "file_type": "unknown",
        "is_malicious": False,
        "yara_matches": [],
        "risk_score": 0,
        "message": "Analysis started."
    }

    try:
        target_url = os.getenv("TARGET_URL")
        filename = os.getenv("FILENAME")

        if not target_url or not filename:
            result_to_output["is_malicious"] = True
            result_to_output["message"] = "TARGET_URL 또는 FILENAME 환경 변수가 설정되지 않았습니다."
            result_to_output["risk_score"] = 100
            logger.error(result_to_output["message"])
            return

        result_to_output["filename"] = filename
        download_path = os.path.join(DOWNLOADS_DIR, filename)
        file_data = None

        logger.info(f"[*] Analysis request for: {target_url} (filename: {filename})")

        if target_url.startswith("data:"):
            logger.info("[*] Detected data URI. Decoding base64 data.")
            match = re.match(r'data:.*?;base64,(.*)', target_url)
            if not match:
                raise ValueError("Invalid data URI format for Base64 decoding.")
            file_data = base64.b64decode(match.group(1))
        else:
            logger.info(f"[*] Downloading file from URL: {target_url}")
            # --- 수정된 부분: headers 인자 추가 ---
            res = requests.get(target_url, headers=DEFAULT_HEADERS, stream=True, timeout=30)
            res.raise_for_status()
            file_data = res.content

        logger.info(f"[*] Attempting to save file to: {download_path}")
        with open(download_path, "wb") as f:
            f.write(file_data)
        logger.info(f"[+] File saved successfully to: {download_path}")
        logger.info(f"[+] Saved file size: {len(file_data)} bytes")

        logger.info("[*] Analyzing file type...")
        file_analyzer = FileTypeAnalyzer()
        file_info = file_analyzer.analyze_file(download_path)
        result_to_output["file_type"] = file_info.get("signature_type", "unknown")
        logger.info(f"[+] File type: {result_to_output['file_type']}")

        logger.info("[*] Performing YARA scan...")
        malware_scanner = MalwareScanner()
        scan_info = malware_scanner.scan_file(download_path)

        result_to_output["is_malicious"] = scan_info.get("is_malicious", False)
        result_to_output["yara_matches"] = scan_info.get("yara_matches", [])
        result_to_output["risk_score"] = scan_info.get("risk_score", 0)

        if result_to_output["is_malicious"]:
            result_to_output["message"] = "악성 파일로 탐지되었습니다."
            logger.warning(f"[!] Malicious file detected. YARA matches: {result_to_output['yara_matches']}")
        else:
            result_to_output["message"] = "안전한 파일입니다."
            logger.info("[+] File deemed safe.")

    except requests.exceptions.RequestException as e:
        result_to_output["is_malicious"] = True
        result_to_output["message"] = f"파일 다운로드 실패: {e}"
        result_to_output["risk_score"] = 80
        result_to_output["analysis_details"] = {"download_error": str(e)}
        logger.error(f"[!] Download error: {e}")
    except ValueError as e:
        result_to_output["is_malicious"] = True
        result_to_output["message"] = f"입력 데이터 오류: {e}"
        result_to_output["risk_score"] = 90
        result_to_output["analysis_details"] = {"input_error": str(e)}
        logger.error(f"[!] Input data error: {e}")
    except Exception as e:
        result_to_output["is_malicious"] = True
        result_to_output["message"] = f"분석 중 예상치 못한 오류 발생: {e}"
        result_to_output["risk_score"] = 100
        result_to_output["analysis_details"] = {"general_error": str(e)}
        logger.exception(f"[!] Unexpected analysis error: {e}")
    finally:
        print("<RESULT>\n" + json.dumps(result_to_output))
        sys.stdout.flush()
        sys.exit(0)

if __name__ == "__main__":
    main()
