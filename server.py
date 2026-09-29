"""MCP-инструмент поиска уязвимостей; Streamable HTTP на /mcp, порт 8001."""

import asyncio
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

if __package__:
    from . import nvd_api
else:
    import nvd_api


SEARCH_TIMEOUT_SECONDS = 40
SEARCH_NOTE = (
    "Поиск по ключевым словам в описаниях NVD, без проверки CPE и версии продукта. "
    "Совпадения могут относиться к другому продукту или расширению; проверяйте описание CVE. "
    "Возвращены первые записи в порядке NVD API, не обязательно самые новые или опасные. "
    "Отсутствие совпадений не доказывает отсутствие уязвимостей."
)

mcp = MCPServer("nist", instructions=(
    "Поиск CVE в NIST NVD по названию проекта. Сначала получите настоящее название "
    "продукта из сведений о GitHub-репозитории: например Visual Studio Code для microsoft/vscode. "
    "Используйте search_vulnerabilities последовательно для каждого проекта. "
    "Передавайте название продукта, а не GitHub URL. no_results означает отсутствие совпадений "
    "по выбранному запросу, а ошибка инструмента — неизвестный результат поиска. "
    "Учитывайте search_note при составлении отчёта."
))


@mcp.tool(annotations=ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True,
))
async def search_vulnerabilities(
    project_name: Annotated[str, Field(
        description="Название продукта для поиска в NVD, например PyTorch или Visual Studio Code; не URL",
        min_length=1, max_length=200,
    )],
    limit: Annotated[int, Field(description="Максимум первых CVE, от 5 до 10", ge=5, le=10)] = 5,
) -> dict[str, Any]:
    """Найти первые 5–10 CVE по названию проекта через NIST API.

    Если совпадений меньше, вернуть доступные, включая пустой список со status=no_results.
    Ошибки сети, API и timeout являются ошибкой инструмента, а не отсутствием CVE.
    """
    if not isinstance(project_name, str) or not project_name.strip() or len(project_name) > 200:
        raise ToolError("Укажите непустое название проекта длиной до 200 символов.")
    if any(ord(char) < 32 or ord(char) == 127 for char in project_name):
        raise ToolError("Название проекта не должно содержать управляющие символы.")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 5 <= limit <= 10:
        raise ToolError("limit должен быть целым числом от 5 до 10.")
    query = " ".join(project_name.split())
    try:
        vulnerabilities = await asyncio.wait_for(
            asyncio.to_thread(nvd_api.search, query, limit), timeout=SEARCH_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        raise ToolError("Превышено время поиска NVD; результат неизвестен. Повторите запрос позже.") from None
    except nvd_api.NVDSearchError as error:
        raise ToolError(str(error)) from None
    return {
        "project_name": query,
        "query": query,
        "status": "ok" if vulnerabilities else "no_results",
        "source": "NVD",
        "limit": limit,
        "returned_count": len(vulnerabilities),
        "limit_reached": len(vulnerabilities) == limit,
        "search_note": SEARCH_NOTE,
        "vulnerabilities": vulnerabilities,
    }


if __name__ == "__main__":
    if __package__:
        from .http_server import run
    else:
        from http_server import run

    run(mcp)
