import requests
import os
import logging
import hashlib
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse
from analyzer.file_type import FileTypeAnalyzer
from analyzer.yara_scan import MalwareScanner


app = Flask(__name__)
CORS(app, origins="*", allow_headers=["Content-Type"], methods=["GET", "POST"])

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('malware_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


DOWNLOAD_DIR = "downloads"
QUARANTINE_DIR = "quarantine"
REPORTS_DIR = "reports"


# 디렉토리 생성
for directory in [DOWNLOAD_DIR, QUARANTINE_DIR, REPORTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# 스캐너 인스턴스 생성
file_analyzer = FileTypeAnalyzer()
malware_scanner = MalwareScanner()

def generate_report(url, filename, scan_result, file_analysis):
    """스캔 결과 보고서를 생성합니다."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "filename": filename,
        "scan_result": scan_result,
        "file_analysis": file_analysis,
        "verdict": "MALICIOUS" if scan_result["is_malicious"] else "CLEAN"
    }
    
    # 보고서 파일로 저장
    report_filename = f"report_{hashlib.md5(url.encode()).hexdigest()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"보고서 저장 완료: {report_path}")
    except Exception as e:
        logger.error(f"보고서 저장 실패: {e}")
    
    return report

def quarantine_file(filepath, reason):
    """악성 파일을 격리합니다."""
    try:
        filename = os.path.basename(filepath)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
        
        # 파일을 격리 폴더로 이동
        os.rename(filepath, quarantine_path)
        
        # 격리 로그 작성
        quarantine_log = {
            "timestamp": datetime.now().isoformat(),
            "original_path": filepath,
            "quarantine_path": quarantine_path,
            "reason": reason
        }
        
        log_path = os.path.join(QUARANTINE_DIR, "quarantine.log")
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(quarantine_log, ensure_ascii=False) + '\n')
        
        logger.warning(f"파일 격리 완료: {filepath} -> {quarantine_path}")
        return quarantine_path
        
    except Exception as e:
        logger.error(f"파일 격리 실패: {e}")
        return None

@app.route("/", methods=["GET"])
def health_check():
    """서버 상태 확인"""
    return jsonify({
        "status": "Server is running",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0",
        "scanner_status": "OK" if malware_scanner.rules else "YARA rules not loaded"
    })

@app.route("/stats", methods=["GET"])
def get_stats():
    """스캔 통계 조회"""
    try:
        reports = []
        if os.path.exists(REPORTS_DIR):
            for filename in os.listdir(REPORTS_DIR):
                if filename.endswith('.json'):
                    reports.append(filename)
        
        quarantine_files = []
        if os.path.exists(QUARANTINE_DIR):
            for filename in os.listdir(QUARANTINE_DIR):
                if not filename.endswith('.log'):
                    quarantine_files.append(filename)
        
        return jsonify({
            "total_scans": len(reports),
            "quarantined_files": len(quarantine_files),
            "reports_directory": REPORTS_DIR,
            "quarantine_directory": QUARANTINE_DIR
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report_download", methods=["POST"])
def report_download():
    """파일 다운로드 보고 및 검사"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload received"}), 400

    url = data.get("url")
    raw_filename = data.get("filename", "")
    
    if not url:
        return jsonify({"error": "URL is required"}), 400

    # 파일 이름 처리
    if not raw_filename or raw_filename.strip().lower() in ["", "unknown", "unknown_file"]:
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or "downloaded.bin"
    else:
        filename = os.path.basename(raw_filename)

    # 안전한 파일명 생성 (중복 방지)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{filename}"
    filepath = os.path.join(DOWNLOAD_DIR, safe_filename)

    logger.info(f"다운로드 요청 - URL: {url}, 파일명: {filename}")

    try:
        # 파일 다운로드
        logger.info(f"파일 다운로드 시작: {url}")
        response = requests.get(url, timeout=30, stream=True)
        response.raise_for_status()

        # 파일 크기 확인 (100MB 제한)
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) > 100 * 1024 * 1024:
            return jsonify({
                "error": "File too large (>100MB)",
                "is_malicious": True
            }), 413

        # 파일 저장
        with open(filepath, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        logger.info(f"파일 다운로드 완료: {filepath}")

        # 파일 분석
        logger.info("파일 분석 시작")
        file_analysis = file_analyzer.analyze_file(filepath)
        scan_result = malware_scanner.scan_file(filepath)
        
        # 보고서 생성
        report = generate_report(url, filename, scan_result, file_analysis)
        
        logger.info(f"스캔 완료 - 파일: {filename}, 악성여부: {scan_result['is_malicious']}, 위험도: {scan_result['risk_score']}")
        
        # 악성 파일 처리
        if scan_result["is_malicious"]:
            quarantine_path = quarantine_file(filepath, f"Malicious file detected - Risk Score: {scan_result['risk_score']}")
            
            response_data = {
                "filename": filename,
                "file_type": file_analysis.get("signature_type", "Unknown"),
                "mime_type": file_analysis.get("mime_type", "Unknown"),
                "is_malicious": True,
                "risk_score": scan_result["risk_score"],
                "yara_matches": [match["rule"] for match in scan_result["yara_matches"]],
                "risk_indicators": file_analysis.get("risk_indicators", []),
                "quarantine_path": quarantine_path,
                "message": f"악성 파일이 탐지되어 격리되었습니다. 위험도: {scan_result['risk_score']}/100"
            }
            
            logger.warning(f"악성 파일 탐지: {filename} (위험도: {scan_result['risk_score']}/100)")
            
        else:
            # 안전한 파일 처리
            response_data = {
                "filename": safe_filename,  # 안전한 파일명 반환
                "file_type": file_analysis.get("signature_type", "Unknown"),
                "mime_type": file_analysis.get("mime_type", "Unknown"),
                "is_malicious": False,
                "risk_score": scan_result["risk_score"],
                "entropy": file_analysis.get("entropy", 0),
                "file_size": file_analysis.get("size", 0),
                "packers": file_analysis.get("packers", []),
                "message": f"파일이 안전하다고 판단됩니다. 위험도: {scan_result['risk_score']}/100"
            }
            
            logger.info(f"안전한 파일: {filename} (위험도: {scan_result['risk_score']}/100)")

        return jsonify(response_data), 200

    except requests.exceptions.Timeout:
        logger.error("다운로드 타임아웃")
        return jsonify({"error": "Download timeout", "is_malicious": True}), 408
    
    except requests.exceptions.RequestException as re:
        logger.error(f"다운로드 실패: {re}")
        return jsonify({"error": f"Download error: {str(re)}", "is_malicious": True}), 500
    
    except Exception as e:
        logger.error(f"처리 중 예외 발생: {e}")
        # 오류 발생 시 임시 파일 정리
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass
        return jsonify({"error": str(e), "is_malicious": True}), 500

@app.route("/safe_download/<filename>", methods=["GET"])
def safe_download(filename):
    """안전한 파일 다운로드"""
    safe_path = os.path.join(DOWNLOAD_DIR, filename)
    
    if not os.path.exists(safe_path):
        logger.warning(f"요청된 파일을 찾을 수 없음: {filename}")
        return jsonify({"error": "File not found"}), 404
    
    try:
        logger.info(f"안전한 파일 다운로드 제공: {filename}")
        return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"파일 전송 실패: {e}")
        return jsonify({"error": "File transfer failed"}), 500

@app.route("/quarantine/list", methods=["GET"])
def list_quarantine():
    """격리된 파일 목록 조회"""
    try:
        quarantine_files = []
        if os.path.exists(QUARANTINE_DIR):
            for filename in os.listdir(QUARANTINE_DIR):
                if not filename.endswith('.log'):
                    file_path = os.path.join(QUARANTINE_DIR, filename)
                    file_info = {
                        "filename": filename,
                        "size": os.path.getsize(file_path),
                        "quarantine_date": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                    }
                    quarantine_files.append(file_info)
        
        return jsonify({
            "quarantine_files": quarantine_files,
            "total_count": len(quarantine_files)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    logger.info("악성코드 탐지 서버 시작")
    logger.info(f"다운로드 디렉토리: {DOWNLOAD_DIR}")
    logger.info(f"격리 디렉토리: {QUARANTINE_DIR}")
    logger.info(f"보고서 디렉토리: {REPORTS_DIR}")
    print()
    
    app.run(host="0.0.0.0", port=8080, debug=False)
