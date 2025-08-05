# controller.py

import docker
import uuid
import os
import json
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

client = docker.from_env()

HOST_DOWNLOADS_PATH = os.getenv("HOST_DOWNLOADS_PATH")
if not HOST_DOWNLOADS_PATH:
    logger.critical("HOST_DOWNLOADS_PATH 환경 변수가 설정되지 않았습니다.")

WORKER_IMAGE = "malware_worker"


def remove_container_if_exists(container_name: str) -> bool:
    try:
        container = client.containers.get(container_name)
        container.remove(force=True)
        logger.info(f"[*] 컨테이너 '{container_name}' 제거됨.")
        return True
    except docker.errors.NotFound:
        return False
    except Exception as e:
        logger.error(f"[!] 컨테이너 '{container_name}' 제거 중 오류 발생: {e}")
        return False

def launch_worker_container(url: str, filename: str) -> dict:
    container_name = f"worker_{uuid.uuid4().hex[:8]}"
    logger.info(f"[*] 새로운 워커 컨테이너 '{container_name}' 생성 시작.")

    volumes = {
        HOST_DOWNLOADS_PATH: {'bind': '/app/downloads', 'mode': 'rw'},
    }
    env = {
        "TARGET_URL": url,
        "FILENAME": filename,
    }

    try:
        # 워커 컨테이너 실행 (비동기, detach=True)
        container = client.containers.run(
            image=WORKER_IMAGE,
            name=container_name,
            environment=env,
            volumes=volumes,
            detach=True         # 컨테이너를 백그라운드에서 실행
        )
        logger.info(f"[*] 워커 컨테이너 '{container_name}' 실행됨. 작업 완료 대기 중...")

        # 컨테이너 작업 완료 또는 타임아웃 대기, worker.py 내부에서 정상적으로 종료되도록 설계되었다면 StatusCode = 0
        result_code = container.wait(timeout=60)["StatusCode"]
        logger.info(f"[*] 워커 컨테이너 '{container_name}' 작업 완료. 종료 코드: {result_code}")

        logs = container.logs().decode("utf-8")
        logger.debug(f"[*] 워커 컨테이너 '{container_name}' 로그:\n{logs}")

        # 작업 완료 후 컨테이너 정리
        remove_container_if_exists(container_name)

        # 워커 스크립트에서 반환하는 JSON 결과 파싱
        try:
            # 워커 스크립트가 "<RESULT>\n" 구분자를 사용하여 JSON을 출력한다고 가정
            raw_result_json = logs.split("<RESULT>\n")[-1].strip()
            result = json.loads(raw_result_json)
            logger.info(f"[*] 워커 컨테이너 결과 파싱 성공: {result.get('is_malicious', 'N/A')}")
        except json.JSONDecodeError as jde:
            logger.error(f"[!] 워커 컨테이너 '{container_name}' 결과 JSON 파싱 실패: {jde}. 원본 로그:\n{logs}")
            result = {"error": "Invalid JSON result from worker", "log": logs, "is_malicious": True, "message": "Failed to parse worker output."}
        except IndexError:
            logger.error(f"[!] 워커 컨테이너 '{container_name}' 로그에서 <RESULT> 구분자를 찾을 수 없음. 원본 로그:\n{logs}")
            result = {"error": "Missing <RESULT> tag in worker log", "log": logs, "is_malicious": True, "message": "Worker did not output expected format."}
        except Exception as ex:
            logger.error(f"[!] 워커 컨테이너 '{container_name}' 결과 처리 중 알 수 없는 오류: {ex}. 원본 로그:\n{logs}")
            result = {"error": str(ex), "log": logs, "is_malicious": True, "message": "Unknown error processing worker output."}

        return result

    except docker.errors.ImageNotFound:
        logger.critical(f"[!] Docker 이미지 '{WORKER_IMAGE}'를 찾을 수 없습니다. 'docker compose --profile build-only build'를 실행했는지 확인하세요.")
        return {"error": f"Docker image '{WORKER_IMAGE}' not found. Please build it.", "is_malicious": True}
    except docker.errors.ContainerError as ce:
        logger.error(f"[!] 워커 컨테이너 '{container_name}' 내부 오류: {ce}. 로그:\n{ce.explanation}")
        remove_container_if_exists(container_name)
        return {"error": f"Container failed with exit code {ce.exit_status}", "log": ce.explanation, "is_malicious": True}
    except docker.errors.APIError as api_err:
        logger.error(f"[!] Docker API 오류 발생: {api_err}. Docker 데몬이 실행 중인지, 권한이 올바른지 확인하세요.")
        remove_container_if_exists(container_name)
        return {"error": f"Docker API error: {api_err}", "is_malicious": True}
    except Exception as e:
        logger.exception(f"[!] 워커 컨테이너 '{container_name}' 실행 중 예상치 못한 오류 발생.")
        remove_container_if_exists(container_name)
        return {"error": str(e), "is_malicious": True, "message": "Unexpected error during worker launch or execution."}
