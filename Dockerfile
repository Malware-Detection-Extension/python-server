FROM python:3.10-slim

# 기본 시스템 패키지와 Docker 클라이언트 설치  
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libmagic-dev \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# requirements 복사 및 설치
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 애플리케이션 파일들 복사
COPY . .

# 필요한 디렉토리 생성
RUN mkdir -p reports quarantine downloads

CMD ["python3", "server.py"]
