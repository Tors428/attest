from groq import AsyncGroq

from attest.config import settings

_client: AsyncGroq | None = None


def _get_client() -> AsyncGroq:
    global _client
    if _client is None:
        _client = AsyncGroq(api_key=settings.groq_api_key)
    return _client


async def generate(prompt: str) -> str:
    client = _get_client()
    response = await client.chat.completions.create(
        model=settings.groq_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
    )
    return response.choices[0].message.content or ""