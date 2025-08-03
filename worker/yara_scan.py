import yara
import hashlib
import os
import magic
import json
from datetime import datetime

class MalwareScanner:
    def __init__(self, rules_path="analyzer/rules.yar"):
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
        """위험도 점수를 계산합니다 (0-100)."""
        score = 0
        
        # YARA 매치 점수
        for match in yara_matches:
            if 'severity' in match['meta']:
                severity = match['meta']['severity']
                if severity == 'critical':
                    score += 40
                elif severity == 'high':
                    score += 30
                elif severity == 'medium':
                    score += 20
                else:
                    score += 10
            else:
                score += 15  # 기본 점수
        
        # 확장자 위험도 점수
        if extension_risk['risk'] == 'high':
            score += 20
        elif extension_risk['risk'] == 'medium':
            score += 10
        
        # 파일 크기 이상 징후 점수
        if size_anomaly:
            if size_anomaly['anomaly'] == 'empty_file':
                score += 15
            elif size_anomaly['anomaly'] == 'tiny_executable':
                score += 25
            elif size_anomaly['anomaly'] == 'large_file':
                score += 5
        
        return min(score, 100)  # 최대 100점

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
