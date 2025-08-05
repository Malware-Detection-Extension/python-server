import os
import csv
import hashlib
from datetime import datetime
from fpdf import FPDF

# 디렉토리 설정
PDF_DIR = "reports/pdf"
CSV_DIR = "reports/csv"
CSV_FILE = os.path.join(CSV_DIR, "report_log.csv")

# 디렉토리 생성
os.makedirs(PDF_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)

# PDF 보고서 생성 및 저장
def generate_pdf_report(report_id, filename, sha256, filetype, yara_matches, is_malicious):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Malware Scan Report", ln=True, align="C")
    pdf.ln(10)

    data = [
        ("Report ID", report_id),
        ("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Filename", filename),
        ("SHA-256", sha256),
        ("File Type", filetype),
        ("YARA Matches", ", ".join(yara_matches) if yara_matches else "None"),
        ("Malicious", "Yes" if is_malicious else "No")
    ]

    for label, value in data:
        pdf.cell(0, 10, txt=f"{label}: {value}", ln=True)

    pdf_path = os.path.join(PDF_DIR, f"{report_id}.pdf")
    pdf.output(pdf_path)

    print(f"[+] PDF report saved: {pdf_path}")
    return pdf_path

# CSV에 메타데이터 누적 기록
def append_to_csv(report_id, filename, sha256, filetype, yara_matches, is_malicious):
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["report_id", "timestamp", "filename", "sha256", "filetype", "yara_matches", "malicious"])
        writer.writerow([
            report_id,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            filename,
            sha256,
            filetype,
            ";".join(yara_matches) if yara_matches else "None",
            "Yes" if is_malicious else "No"
        ])
    print(f"[+] Report metadata appended to CSV: {CSV_FILE}")

# 전체 보고서 저장
def save_report(file_path, yara_matches, is_malicious):
    filename = os.path.basename(file_path)
    
    # SHA-256 해시 계산
    with open(file_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    report_id = sha256[:12]  # report ID로 SHA256 앞 12자리 사용
    filetype = os.path.splitext(filename)[-1][1:] or "unknown"

    # PDF 보고서 생성
    generate_pdf_report(report_id, filename, sha256, filetype, yara_matches, is_malicious)

    # CSV 메타데이터 누적
    append_to_csv(report_id, filename, sha256, filetype, yara_matches, is_malicious)

    return report_id
