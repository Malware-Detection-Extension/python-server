#!/bin/bash

# Docker Compose 재빌드 및 실행 스크립트
# 실행 방법: ./rebuild.sh

set -e  # 오류 발생 시 스크립트 중단

echo "=== Docker Compose 컨테이너 중지 중... ==="
docker compose down

echo "=== Docker Compose 이미지 빌드 중... ==="
docker compose --profile build-only build
docker compose build

echo "=== Docker Compose 컨테이너 시작 중... ==="
docker compose up -d

echo "=== 완료! 컨테이너가 백그라운드에서 실행 중입니다. ==="
echo "컨테이너 상태 확인: docker compose ps"
echo "로그 확인: docker compose logs -f"
