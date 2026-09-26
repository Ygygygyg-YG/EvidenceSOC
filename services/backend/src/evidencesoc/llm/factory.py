from langchain_openai import ChatOpenAI

from evidencesoc.config import Settings, get_settings


def create_llm(settings: Settings | None = None, *, max_retries: int = 2) -> ChatOpenAI:
    settings = settings or get_settings()

    if settings.llm_mode != "deepseek":
        raise RuntimeError(
            f"当前 LLM_MODE={settings.llm_mode}，不是 deepseek"
        )

    if settings.deepseek_api_key is None:
        raise RuntimeError("缺少 DEEPSEEK_API_KEY")

    return ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=0,
        timeout=60,
        max_retries=max_retries,
    )
