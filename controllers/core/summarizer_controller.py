from typing import Any, Dict

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from llm_summarizer import ThreatSummarizer


summarizer = ThreatSummarizer()


async def generate_threat_summary(threat_data: Dict[str, Any]) -> JSONResponse:
    """Generate an executive threat summary without exposing the Groq key to the client."""
    try:
        summary = summarizer.generate_summary(
            threat_data=threat_data,
            provider="Groq",
            model_name="openai/gpt-oss-20b",
        )
        return JSONResponse(content={"summary": summary, "provider": "Groq", "model": "openai/gpt-oss-20b"})
    except (ImportError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Groq summary generation failed: {exc}") from exc
