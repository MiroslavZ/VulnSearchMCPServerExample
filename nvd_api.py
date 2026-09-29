"""Ограниченный синхронный поиск через nvdlib 0.9.0."""

import logging
import os
import re
import threading
import time
from typing import Any
from urllib.parse import quote

import nvdlib
import requests


REQUEST_DELAY_SECONDS = 0.7
_request_lock = threading.Lock()


class NVDSearchError(Exception):
    """Безопасная для передачи агенту ошибка без API-ключа и HTTP body."""


class _NVDLogCapture(logging.Handler):
    """nvdlib 0.9.0 логирует неверный JSON и возвращает [] вместо исключения."""

    def __init__(self):
        super().__init__(logging.ERROR)
        self.thread_id = threading.get_ident()
        self.failed = False

    def emit(self, record: logging.LogRecord):
        if record.thread == self.thread_id:
            self.failed = True


def _cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for key, version in (
        ("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key, [])
        if not entries:
            continue
        primary = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
        data = primary["cvssData"]
        return {
            "version": version,
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or primary.get("baseSeverity"),
        }
    return {"version": None, "score": None, "severity": None}


def _vulnerability(cve: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve["id"]
    if not isinstance(cve_id, str) or re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id) is None:
        raise ValueError("Invalid CVE identifier")
    descriptions = cve.get("descriptions", [])
    description = next((item["value"] for item in descriptions if item.get("lang") == "en"), None)
    if description is None and descriptions:
        description = descriptions[0].get("value")
    return {
        "id": cve_id,
        "description": description,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cvss": _cvss(cve.get("metrics", {})),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
    }


def search(project_name: str, limit: int) -> list[dict[str, Any]]:
    """Один запрос, без пагинации/ретраев; выполняется только в worker thread."""
    api_token = os.getenv("NIST_API_TOKEN", "").strip()
    if not api_token:
        raise NVDSearchError("На сервере не задан NIST_API_TOKEN.")
    # Lock живёт в worker: timeout/cancel MCP-запроса не допускает второго
    # HTTP-запроса, пока первый реально не завершился.
    if not _request_lock.acquire(blocking=False):
        raise NVDSearchError("NVD занят предыдущим запросом. Выполняйте поиск проектов последовательно.")
    started = time.monotonic()
    log = logging.getLogger("nvdlib.get")
    capture = _NVDLogCapture()
    previous_level = log.level
    log.addHandler(capture)
    # ERROR обязан попасть в capture даже при глобальном уровне CRITICAL.
    log.setLevel(logging.ERROR)
    try:
        # searchCVE сам не кодирует keywordSearch; '&' не должен становиться
        # дополнительным параметром NVD API. limit ограничивает одну страницу.
        # В 0.9.0 нет verbose; searchCVE_V2 имеет бесконечный retry при HTTP 403.
        records = nvdlib.searchCVE(
            keywordSearch=quote(project_name, safe=""),
            noRejected=True, limit=limit, key=api_token,
            delay=REQUEST_DELAY_SECONDS, asDict=True,
        )
        if capture.failed or not isinstance(records, list):
            raise NVDSearchError("NVD вернул некорректный ответ; результат поиска неизвестен.")
        return [_vulnerability(record) for record in records[:limit]]
    except requests.Timeout:
        raise NVDSearchError("Превышено время ожидания NVD API; результат поиска неизвестен.") from None
    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else None
        if status in {401, 403}:
            message = "NVD отклонил запрос: проверьте API-ключ и квоту запросов."
        elif status == 429:
            message = "Превышена квота NVD API. Повторите поиск позже."
        else:
            message = f"Ошибка NVD API (HTTP {status})." if status else "Ошибка HTTP при обращении к NVD API."
        raise NVDSearchError(message + " Результат поиска неизвестен.") from None
    except requests.RequestException:
        raise NVDSearchError("Не удалось соединиться с NVD API; результат поиска неизвестен.") from None
    except (KeyError, TypeError, ValueError, AttributeError, LookupError):
        raise NVDSearchError("NVD вернул некорректный ответ; результат поиска неизвестен.") from None
    finally:
        log.removeHandler(capture)
        log.setLevel(previous_level)
        # nvdlib ждёт delay после успешного ответа; при ошибках сохраняем
        # минимальный интервал, чтобы последующие вызовы не исчерпали квоту.
        remaining = REQUEST_DELAY_SECONDS - (time.monotonic() - started)
        try:
            if remaining > 0:
                time.sleep(remaining)
        finally:
            _request_lock.release()
