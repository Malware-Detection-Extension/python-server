#!/bin/bash

echo "📦 Python 패키지 설치 중 (pip 업그레이드)..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🐳 Docker 설치 여부 확인..."
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker가 설치되어 있지 않습니다. 설치를 진행합니다..."
    sudo apt-get update
    sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg lsb-release
    
    # Docker 공식 GPG 키 추가
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/docker.gpg
    
    # Docker APT 저장소 추가
    echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io

    echo "🐳 Docker Compose Plugin 설치 중..."
    sudo apt-get install -y docker-compose-plugin

    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker $USER
    echo "✅ Docker 설치 완료. 재로그인 필요이 필요할 수 있습니다."
else
    echo "✅ Docker는 이미 설치되어 있습니다."
fi

echo "📁 디렉토리 초기화 중 (host volume for reports, downloads, quarantine)..."
mkdir -p downloads quarantine reports

echo "✅ 설치 완료!"
echo "💡 재로그인 후 'malware-detection-extension/python-server' 디렉토리로 이동하여 다음 명령 실행:"
echo "   1. docker compose --profile build-only build  (워커 이미지 빌드)"
echo "   2. docker compose up -d                       (모든 서비스 실행)"
