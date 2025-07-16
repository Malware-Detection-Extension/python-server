import docker
import uuid
import time
import shutil
import os
import json

client = docker.from_env()
BASE_PATH = os.path.dirname(__file__)

WORKER_IMAGE = "malware_worker"


def remove_container_if_exists(container_name):
    """컨테이너가 존재하면 제거하는 함수"""
    try:
        container = client.containers.get(container_name)
        container.remove(force=True)
        print(f"[*] 컨테이너 '{container_name}' 제거됨")
        return True
    except docker.errors.NotFound:
        print(f"[*] 컨테이너 '{container_name}' 찾을 수 없음")
        return False
    except Exception as e:
        print(f"[!] 컨테이너 '{container_name}' 제거 중 오류: {e}")
        return False


def launch_worker_container(url, filename):
    container_name = f"worker_{uuid.uuid4().hex[:8]}"

    # 기존 컨테이너가 있다면 제거
    remove_container_if_exists(container_name)

    # 생성
    volumes = {
        os.path.join(BASE_PATH, "downloads"): {'bind': '/app/downloads', 'mode': 'rw'},
    }
    env = {
        "TARGET_URL": url,
        "FILENAME": filename,
    }
    try:
        container = client.containers.run(
            image=WORKER_IMAGE,
            name=container_name,
            environment=env,
            volumes=volumes,
            detach=True
        )
        exit_code = container.wait(timeout=60)["StatusCode"]
        logs = container.logs().decode("utf-8")
        
        # 컨테이너 정리
        remove_container_if_exists(container_name)

        # 결과 json 구현 검사 결과 만으면
        try:
            result = json.loads(logs.split("<RESULT>\n")[-1].strip())
        except:
            result = {"error": "Invalid result", "log": logs, "is_malicious": True}
        return result

    except Exception as e:
        # 에러 발생 시에도 컨테이너 정리
        remove_container_if_exists(container_name)
        return {"error": str(e), "is_malicious": True}
