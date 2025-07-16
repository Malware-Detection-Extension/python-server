import magic
import os
import struct
import hashlib

class FileTypeAnalyzer:
    def __init__(self):
        self.magic_signatures = {
            # 실행 파일
            b'MZ': 'PE Executable',
            b'\x7fELF': 'ELF Executable',
            b'\xfe\xed\xfa\xce': 'Mach-O Executable (32-bit)',
            b'\xfe\xed\xfa\xcf': 'Mach-O Executable (64-bit)',
            
            # 아카이브 파일
            b'PK\x03\x04': 'ZIP Archive',
            b'Rar!\x1a\x07\x00': 'RAR Archive',
            b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
            
            # 스크립트 파일
            b'#!/bin/bash': 'Bash Script',
            b'#!/bin/sh': 'Shell Script',
            b'@echo off': 'Batch Script',
            
            # 문서 파일
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'Microsoft Office Document',
            b'%PDF': 'PDF Document',
            
            # 이미지 파일
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x89PNG\r\n\x1a\n': 'PNG Image',
            b'GIF87a': 'GIF Image',
            b'GIF89a': 'GIF Image',
        }
    
    def get_file_signature(self, file_path):
        """파일의 시그니처를 확인합니다."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)  # 처음 32바이트 읽기
                
            for signature, file_type in self.magic_signatures.items():
                if header.startswith(signature):
                    return file_type
                    
        except Exception as e:
            print(f"[!] 파일 시그니처 확인 실패: {e}")
        
        return "Unknown"
    
    def analyze_pe_file(self, file_path):
        """PE 파일을 분석합니다."""
        try:
            with open(file_path, 'rb') as f:
                # DOS 헤더 확인
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return None
                
                # PE 헤더 오프셋 읽기
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # PE 시그니처 확인
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    return None
                
                # COFF 헤더 읽기
                coff_header = f.read(20)
                machine = struct.unpack('<H', coff_header[0:2])[0]
                number_of_sections = struct.unpack('<H', coff_header[2:4])[0]
                time_date_stamp = struct.unpack('<I', coff_header[4:8])[0]
                
                # Optional 헤더 읽기
                optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
                if optional_header_size > 0:
                    optional_header = f.read(optional_header_size)
                    if len(optional_header) >= 2:
                        magic = struct.unpack('<H', optional_header[0:2])[0]
                        pe_type = "PE32+" if magic == 0x20b else "PE32"
                    else:
                        pe_type = "PE32"
                else:
                    pe_type = "PE32"
                
                return {
                    "type": pe_type,
                    "machine": machine,
                    "sections": number_of_sections,
                    "timestamp": time_date_stamp,
                    "architecture": "x64" if machine == 0x8664 else "x86"
                }
                
        except Exception as e:
            print(f"[!] PE 파일 분석 실패: {e}")
        
        return None
    
    def check_file_entropy(self, file_path):
        """파일의 엔트로피를 계산합니다 (패킹 탐지용)."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # 바이트 빈도 계산
            frequency = [0] * 256
            for byte in data:
                frequency[byte] += 1
            
            # 엔트로피 계산
            entropy = 0.0
            data_len = len(data)
            
            for count in frequency:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception as e:
            print(f"[!] 엔트로피 계산 실패: {e}")
            return 0.0
    
    def detect_packer(self, file_path):
        """패커 탐지를 수행합니다."""
        packers = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # 일반적인 패커 시그니처
            packer_signatures = {
                b'UPX!': 'UPX',
                b'UPX0': 'UPX',
                b'UPX1': 'UPX',
                b'FSG!': 'FSG',
                b'MPRESS': 'MPRESS',
                b'aPLib': 'aPLib',
                b'NsPack': 'NsPack'
            }
            
            for signature, packer_name in packer_signatures.items():
                if signature in data:
                    packers.append(packer_name)
            
            # 높은 엔트로피는 패킹 가능성을 시사
            entropy = self.check_file_entropy(file_path)
            if entropy > 7.5:  # 높은 엔트로피 임계값
                packers.append("High Entropy (Possibly Packed)")
            
        except Exception as e:
            print(f"[!] 패커 탐지 실패: {e}")
        
        return packers
    
    def analyze_file(self, file_path):
        """파일을 종합적으로 분석합니다."""
        result = {
            "filename": os.path.basename(file_path),
            "size": 0,
            "signature_type": "Unknown",
            "mime_type": "Unknown",
            "magic_type": "Unknown",
            "pe_info": None,
            "entropy": 0.0,
            "packers": [],
            "is_executable": False,
            "is_archive": False,
            "is_document": False,
            "risk_indicators": []
        }
        
        if not os.path.exists(file_path):
            result["error"] = "파일이 존재하지 않습니다"
            return result
        
        try:
            # 파일 크기
            result["size"] = os.path.getsize(file_path)
            
            # 시그니처 기반 타입 확인
            result["signature_type"] = self.get_file_signature(file_path)
            
            # Magic 라이브러리로 타입 확인
            try:
                result["magic_type"] = magic.from_file(file_path)
                result["mime_type"] = magic.from_file(file_path, mime=True)
            except:
                pass
            
            # PE 파일 분석
            if result["signature_type"] == "PE Executable":
                result["pe_info"] = self.analyze_pe_file(file_path)
                result["is_executable"] = True
            
            # 엔트로피 계산
            result["entropy"] = self.check_file_entropy(file_path)
            
            # 패커 탐지
            result["packers"] = self.detect_packer(file_path)
            
            # 파일 유형 분류
            if any(keyword in result["signature_type"].lower() for keyword in ["executable", "pe", "elf", "mach-o"]):
                result["is_executable"] = True
            
            if any(keyword in result["signature_type"].lower() for keyword in ["archive", "zip", "rar", "7-zip"]):
                result["is_archive"] = True
            
            if any(keyword in result["signature_type"].lower() for keyword in ["document", "pdf", "office"]):
                result["is_document"] = True
            
            # 위험 지표 확인
            risk_indicators = []
            
            # 높은 엔트로피
            if result["entropy"] > 7.5:
                risk_indicators.append("High entropy (possibly packed or encrypted)")
            
            # 패커 사용
            if result["packers"]:
                risk_indicators.append(f"Packed with: {', '.join(result['packers'])}")
            
            # 의심스러운 확장자와 실제 파일 타입 불일치
            filename = result["filename"].lower()
            if filename.endswith(('.txt', '.doc', '.pdf', '.jpg', '.png')) and result["is_executable"]:
                risk_indicators.append("File extension mismatch (executable disguised as document/image)")
            
            # 작은 실행 파일
            if result["is_executable"] and result["size"] < 1024:
                risk_indicators.append("Unusually small executable file")
            
            result["risk_indicators"] = risk_indicators
            
        except Exception as e:
            result["error"] = f"분석 중 오류 발생: {str(e)}"
        
        return result

# 기존 함수와의 호환성을 위한 래퍼 함수
def get_file_type(file_path):
    """기존 코드와의 호환성을 위한 함수"""
    analyzer = FileTypeAnalyzer()
    result = analyzer.analyze_file(file_path)
    
    if result.get('error'):
        return f"Unknown ({result['error']})"
    
    # 상세한 정보를 포함한 문자열 반환
    type_info = result['signature_type']
    
    if result['pe_info']:
        type_info += f" ({result['pe_info']['architecture']})"
    
    if result['packers']:
        type_info += f" [Packed: {', '.join(result['packers'])}]"
    
    if result['risk_indicators']:
        type_info += f" [Risk: {len(result['risk_indicators'])} indicators]"
    
    return type_info
