import yara
import hashlib
import os
import magic
import json
from datetime import datetime

class MalwareScanner:
    def __init__(self, rules_path="./rules/rules_combined.yar"):
        self.rules_path = rules_path
        self.rules = None
        self.load_rules()
    
    def load_rules(self):
        """YARA 규칙을 로드합니다."""
        try:
            self.rules = yara.compile(filepath=self.rules_path)
            print(f"[+] YARA 규칙 로드 완료: {self.rules_path}")
        except Exception as e:
            print(f"[!] YARA 규칙 로드 실패: {e}")
            self.rules = None
    
    def get_file_hash(self, file_path):
        """파일의 해시값을 계산합니다."""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            print(f"[!] 해시 계산 실패: {e}")
        return hashes
    
    def get_file_info(self, file_path):
        """파일의 기본 정보를 수집합니다."""
        info = {
            'filename': os.path.basename(file_path),
            'size': 0,
            'file_type': 'Unknown',
            'mime_type': 'Unknown'
        }
        
        try:
            # 파일 크기
            info['size'] = os.path.getsize(file_path)
            
            # 파일 타입 (magic number 기반)
            info['file_type'] = magic.from_file(file_path)
            info['mime_type'] = magic.from_file(file_path, mime=True)
            
        except Exception as e:
            print(f"[!] 파일 정보 수집 실패: {e}")
        
        return info
    
    def check_file_size_anomaly(self, file_path):
        """파일 크기 이상 징후를 확인합니다."""
        try:
            size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            
            # 의심스러운 크기 패턴
            if size == 0:
                return {"anomaly": "empty_file", "description": "파일이 비어있습니다"}
            
            # 일반적이지 않은 크기의 실행 파일
            if filename.lower().endswith('.exe') and size < 1024:
                return {"anomaly": "tiny_executable", "description": "실행 파일이 너무 작습니다"}
            
            # 매우 큰 파일 (100MB 이상)
            if size > 100 * 1024 * 1024:
                return {"anomaly": "large_file", "description": "파일이 매우 큽니다"}
                
        except Exception as e:
            print(f"[!] 파일 크기 확인 실패: {e}")
        
        return None
    
    def check_suspicious_extensions(self, file_path):
        """의심스러운 파일 확장자를 확인합니다."""
        filename = os.path.basename(file_path).lower()
        
        # 높은 위험도 확장자
        high_risk_extensions = [
            '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', 
            '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf', 
            '.wsh', '.ps1', '.ps1xml', '.ps2', '.ps2xml', 
            '.psc1', '.psc2', '.msh', '.msh1', '.msh2', 
            '.mshxml', '.msh1xml', '.msh2xml'
        ]
        
        # 중간 위험도 확장자
        medium_risk_extensions = [
            '.jar', '.zip', '.rar', '.7z', '.iso', '.img',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.rtf'
        ]
        
        for ext in high_risk_extensions:
            if filename.endswith(ext):
                return {"risk": "high", "extension": ext}
        
        for ext in medium_risk_extensions:
            if filename.endswith(ext):
                return {"risk": "medium", "extension": ext}
        
        return {"risk": "low", "extension": os.path.splitext(filename)[1]}
    
    def scan_file(self, file_path):
        """파일을 종합적으로 스캔합니다."""
        if not self.rules:
            return {
                "error": "YARA 규칙이 로드되지 않았습니다",
                "is_malicious": False
            }
        
        if not os.path.exists(file_path):
            return {
                "error": "파일이 존재하지 않습니다",
                "is_malicious": False
            }
        
        # 기본 정보 수집
        file_info = self.get_file_info(file_path)
        file_hashes = self.get_file_hash(file_path)
        
        # 의심스러운 패턴 확인
        size_anomaly = self.check_file_size_anomaly(file_path)
        extension_risk = self.check_suspicious_extensions(file_path)
        
        # YARA 스캔 실행
        yara_matches = []
        try:
            matches = self.rules.match(file_path)
            yara_matches = [
                {
                    "rule": match.rule,
                    "meta": match.meta,
                    "strings": [
                        {
                            "identifier": s.identifier,
                            "offset": s.offset,
                            "data": s.data.decode('utf-8', errors='ignore')
                        } for s in match.strings
                    ]
                }
                for match in matches
            ]
        except Exception as e:
            print(f"[!] YARA 스캔 실패: {e}")
        
        # 위험도 계산
        risk_score = self.calculate_risk_score(yara_matches, extension_risk, size_anomaly)
        
        # 결과 구성
        result = {
            "timestamp": datetime.now().isoformat(),
            "file_info": file_info,
            "hashes": file_hashes,
            "yara_matches": yara_matches,
            "extension_risk": extension_risk,
            "size_anomaly": size_anomaly,
            "risk_score": risk_score,
            "is_malicious": risk_score >= 70  # 70점 이상이면 악성으로 판단
        }
        
        return result
    
    def calculate_risk_score(self, yara_matches, extension_risk, size_anomaly):
        score = 0
        yara_score = 0
    
        # 1. YARA 매치 점수 (누적 합산 및 우선순위 지정)
        max_yara_score_from_cumulative = 0
        for match in yara_matches:
            severity = match['meta'].get('severity', 'low')
            if severity == 'critical':
                return 100  # 치명적인 위협 발견 시 즉시 100점
            elif severity == 'high':
                yara_score = max(yara_score, 70)
            elif severity == 'medium':
                # medium 룰 여러 개가 누적되도록 점수를 합산
                max_yara_score_from_cumulative += 15 
            elif severity == 'low':
                # low 룰 여러 개가 누적되도록 점수를 합산
                max_yara_score_from_cumulative += 5

        # high 룰에 걸리지 않았을 때만 누적 점수 적용 (최대 점수 40점)
        if yara_score < 70:
            yara_score = max(yara_score, min(max_yara_score_from_cumulative, 40))

        # 2. 확장자 위험도 점수
        extension_score = 0
        risk_level = extension_risk.get('risk', 'low')
        if risk_level == 'high':
            extension_score = 30
        elif risk_level == 'medium':
            extension_score = 15

        # 3. 파일 크기 이상 징후 점수
        anomaly_score = 0
        if size_anomaly:
            if size_anomaly['anomaly'] == 'tiny_executable':
                anomaly_score = 25
            elif size_anomaly['anomaly'] == 'empty_file':
                anomaly_score = 10
            elif size_anomaly['anomaly'] == 'large_file':
                anomaly_score = 5

        # 4. 최종 점수 합산
        score = yara_score + extension_score + anomaly_score
        return min(score, 100)

# 기존 함수와의 호환성을 위한 래퍼 함수
def scan_with_yara(file_path):
    """기존 코드와의 호환성을 위한 함수"""
    scanner = MalwareScanner()
    result = scanner.scan_file(file_path)
    
    if result.get('error'):
        return [result['error']]
    
    if result['is_malicious']:
        matches = []
        for match in result['yara_matches']:
            matches.append(match['rule'])
        return matches
    
    return []
