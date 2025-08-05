// Word 문서 관련
include "./documents/doc_macros.yar"
include "./documents/docx_macros.yar"
include "./documents/pdf_payloads.yar"
include "./documents/rtf_exploits.yar"
include "./documents/ppt_macros.yar"
include "./documents/excel_macros.yar"

// 기타 포맷
include "./spreadsheets/base64_payloads.yar"
include "./images/hidden_payloads.yar"
include "./media/suspicious_metadata.yar"

// 실행 파일
include "./executables/suspicious_pe.yar"
include "./executables/packed_exe.yar"
include "./executables/malicious_scripts.yar"

// 압축/이메일
include "./archives/executable_in_archive.yar"
include "./emails/base64_payloads.yar"