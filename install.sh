#!/bin/bash

echo "📦 Python 패키지 설치 중..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🧱 시스템 패키지 설치 중 (libmagic, yara 등)..."
sudo apt-get update
sudo apt-get install -y libmagic1 libmagic-dev yara

echo "📁 다운로드 폴더 생성 중..."
mkdir -p downloads

echo "✅ 설치 완료!"
echo "💡 서버 실행: python server.py"
