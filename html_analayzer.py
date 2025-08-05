# html_analyzer.py

import requests
from bs4 import BeautifulSoup
import re
import logging
from urllib.parse import urlparse # URL 파싱을 위해 추가

logger = logging.getLogger("html_analyzer")
logger.setLevel(logging.INFO)

class HtmlAnalyzer:
    def __init__(self):
        # 의심스러운 JavaScript 패턴 (예시)
        self.suspicious_js_patterns = [
            re.compile(r'eval\s*\('),
            re.compile(r'document\.write\s*\('),
            re.compile(r'unescape\s*\('),
            re.compile(r'atob\s*\('), # Base64 디코딩
            re.compile(r'fromCharCode\s*\('), # 동적 코드 생성
            re.compile(r'location\.href\s*='), # 리다이렉션
            re.compile(r'window\.open\s*\('), # 팝업/새 창
            re.compile(r'setTimeout\s*\(\s*["\']\s*[^"\']+\s*["\']'), # 문자열 인자 setTimeout
            re.compile(r'setInterval\s*\(\s*["\']\s*[^"\']+\s*["\']'), # 문자열 인자 setInterval
            re.compile(r'Coinhive\.Anonymous'), # 암호화폐 채굴
            re.compile(r'XMLHttpRequest\.open\s*\(\s*["\']POST'), # 의심스러운 POST 요청
        ]

        # 의심스러운 HTML 요소/속성 패턴
        self.suspicious_html_patterns = [
            re.compile(r'<iframe[^>]*src=["\'](data:|javascript:|http(s)?://[^"\']*?\.exe)[^>]*>', re.IGNORECASE), # 의심스러운 iframe 소스
            re.compile(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*url=[^>]*>', re.IGNORECASE), # 메타 리프레시 리다이렉션
            re.compile(r'display:\s*none', re.IGNORECASE), # 숨겨진 요소
            re.compile(r'visibility:\s*hidden', re.IGNORECASE), # 숨겨진 요소
            re.compile(r'opacity:\s*0', re.IGNORECASE), # 투명한 요소
        ]

    def analyze_url(self, url: str) -> dict:
        """
        주어진 URL의 HTML 콘텐츠를 가져와 정적으로 분석합니다.
        """
        analysis_result = {
            "is_malicious": False,
            "message": "HTML 분석 완료.",
            "risk_score": 0,
            "analysis_details": {
                "url": url,
                "html_fetched": False,
                "html_size_bytes": 0,
                "suspicious_js_patterns_found": [],
                "suspicious_html_elements_found": [],
                "external_scripts": [],
                "inline_scripts_analyzed": 0,
                "redirections_detected": [],
                "form_actions_analyzed": []
            }
        }

        try:
            logger.info(f"[*] Fetching HTML content from: {url}")
            response = requests.get(url, timeout=15)
            response.raise_for_status() # HTTP 오류 발생 시 예외 발생
            html_content = response.text
            analysis_result["analysis_details"]["html_fetched"] = True
            analysis_result["analysis_details"]["html_size_bytes"] = len(html_content.encode('utf-8'))
            logger.info(f"[+] HTML content fetched. Size: {analysis_result['analysis_details']['html_size_bytes']} bytes.")

            soup = BeautifulSoup(html_content, 'lxml') # lxml 파서 사용

            # 1. JavaScript 분석
            for script in soup.find_all('script'):
                script_content = script.string # 인라인 스크립트
                script_src = script.get('src') # 외부 스크립트

                if script_src:
                    analysis_result["analysis_details"]["external_scripts"].append(script_src)
                    # TODO: 외부 스크립트 URL의 평판 조회 또는 내용 추가 분석 (선택 사항)
                elif script_content:
                    analysis_result["analysis_details"]["inline_scripts_analyzed"] += 1
                    for pattern in self.suspicious_js_patterns:
                        if pattern.search(script_content):
                            match_name = pattern.pattern.replace('\\s*', '').replace('\\(', '(') # 패턴 이름 간소화
                            analysis_result["analysis_details"]["suspicious_js_patterns_found"].append(match_name)
                            analysis_result["is_malicious"] = True
                            analysis_result["risk_score"] += 20
                            logger.warning(f"[!] Suspicious JS pattern found: {match_name}")

            # 2. HTML 요소 분석
            # iframe 분석
            for iframe in soup.find_all('iframe'):
                iframe_src = iframe.get('src')
                if iframe_src and (iframe_src.startswith('data:') or iframe_src.startswith('javascript:')):
                    analysis_result["analysis_details"]["suspicious_html_elements_found"].append(f"iframe_data_js_src: {iframe_src[:50]}...")
                    analysis_result["is_malicious"] = True
                    analysis_result["risk_score"] += 30
                    logger.warning(f"[!] Suspicious iframe src found: {iframe_src}")

            # meta refresh 분석
            for meta in soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.IGNORECASE)}):
                content = meta.get('content')
                if content and 'url=' in content.lower():
                    refresh_url_match = re.search(r'url=(.*?)(;|$)', content, re.IGNORECASE)
                    refresh_url = refresh_url_match.group(1) if refresh_url_match else content
                    analysis_result["analysis_details"]["redirections_detected"].append(f"meta_refresh: {refresh_url}")
                    analysis_result["is_malicious"] = True
                    analysis_result["risk_score"] += 25
                    logger.warning(f"[!] Meta refresh redirection detected: {refresh_url}")

            # 숨겨진 요소 분석 (CSS 스타일 속성)
            for tag in soup.find_all(True): # 모든 태그
                style = tag.get('style')
                if style:
                    for pattern in self.suspicious_html_patterns:
                        if pattern.search(style):
                            match_name = pattern.pattern.replace('\\s*', '').replace('\\(', '(')
                            analysis_result["analysis_details"]["suspicious_html_elements_found"].append(f"hidden_element_style: {tag.name} ({match_name})")
                            analysis_result["risk_score"] += 10 # 숨김 자체는 위험도가 낮을 수 있음
                            logger.info(f"[!] Hidden element style found: {tag.name} with {match_name}")

            # form action 분석 (피싱 의심)
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    current_domain = urlparse(url).netloc
                    action_domain = urlparse(action).netloc
                    
                    if action_domain and action_domain != current_domain:
                        analysis_result["analysis_details"]["form_actions_analyzed"].append(f"external_form_action: {action}")
                        analysis_result["is_malicious"] = True
                        analysis_result["risk_score"] += 40
                        logger.warning(f"[!] External form action detected: {action}")
                    else:
                        analysis_result["analysis_details"]["form_actions_analyzed"].append(f"internal_form_action: {action}")

            # 최종 위험 점수 기반 메시지 업데이트
            if analysis_result["risk_score"] > 0 and not analysis_result["is_malicious"]:
                analysis_result["is_malicious"] = True # 위험 점수가 있으면 악성으로 간주
                analysis_result["message"] = f"의심스러운 HTML/JS 패턴이 발견되었습니다. (위험 점수: {analysis_result['risk_score']})"
            elif analysis_result["risk_score"] == 0 and not analysis_result["is_malicious"]:
                analysis_result["message"] = "HTML/JS에서 특이한 패턴이 발견되지 않았습니다."


        except requests.exceptions.RequestException as e:
            analysis_result["is_malicious"] = True
            analysis_result["message"] = f"HTML 콘텐츠 다운로드 실패: {e}"
            analysis_result["risk_score"] = 80
            analysis_result["analysis_details"]["error"] = str(e)
            logger.error(f"[!] HTML download error: {e}")
        except Exception as e:
            analysis_result["is_malicious"] = True
            analysis_result["message"] = f"HTML 분석 중 예상치 못한 오류 발생: {e}"
            analysis_result["risk_score"] = 100
            analysis_result["analysis_details"]["error"] = str(e)
            logger.exception(f"[!] Unexpected HTML analysis error: {e}")
        
        return analysis_result

