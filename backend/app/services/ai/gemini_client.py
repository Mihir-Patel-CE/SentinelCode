import json
import httpx
from typing import List, Tuple
from app.services.ai.base import BaseAIProvider
from app.schemas.review import FindingCreate
from app.core.logging import logger

GEMINI_PROMPT = """You are an expert Principal Security Engineer and Static Code Reviewer.
Analyze the provided code and return ONLY a valid JSON object matching this schema:
{
  "summary": "2-3 sentences summarizing the code review",
  "findings": [
    {
      "rule_id": "AI-SEC-XXX",
      "title": "Issue title",
      "description": "Clear explanation of risk and impact",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "category": "security" | "bug" | "quality" | "performance" | "style",
      "line_start": 1,
      "line_end": 2,
      "suggested_fix": "Fix explanation",
      "fix_diff": "- bad_code\\n+ good_code"
    }
  ]
}
"""


class GeminiAIProvider(BaseAIProvider):
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model = model

    @property
    def provider_name(self) -> str:
        return f"gemini-{self.model}"

    async def analyze(
        self,
        code: str,
        language: str,
        static_findings: List[FindingCreate]
    ) -> Tuple[List[FindingCreate], str]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        
        prompt_text = f"{GEMINI_PROMPT}\n\nLanguage: {language}\nCode:\n```{language}\n{code}\n```"
        payload = {
            "contents": [{
                "parts": [{"text": prompt_text}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "response_mime_type": "application/json"
            }
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(url, json=payload)
                res.raise_for_status()
                data = res.json()
                raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(raw_text)

                findings: List[FindingCreate] = []
                for item in parsed.get("findings", []):
                    findings.append(FindingCreate(
                        rule_id=item.get("rule_id", "AI-GEM-001"),
                        title=item.get("title", "AI Identified Issue"),
                        description=item.get("description", ""),
                        severity=item.get("severity", "medium").lower(),
                        category=item.get("category", "bug").lower(),
                        source="ai",
                        line_start=item.get("line_start"),
                        line_end=item.get("line_end"),
                        suggested_fix=item.get("suggested_fix"),
                        fix_diff=item.get("fix_diff")
                    ))
                summary = parsed.get("summary", "Gemini analysis completed.")
                return findings, summary
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            raise
