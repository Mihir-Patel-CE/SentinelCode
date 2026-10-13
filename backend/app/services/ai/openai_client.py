import json
import httpx
from typing import List, Tuple, Optional
from app.services.ai.base import BaseAIProvider
from app.schemas.review import FindingCreate
from app.core.logging import logger


SYSTEM_PROMPT = """You are an expert Principal Security Engineer and Static Code Reviewer.
Analyze the provided source code for:
1. Critical security bugs (SQL injection, XSS, RCE, IDOR, SSRF, Broken Auth).
2. Logic defects, race conditions, edge-case null dereferences.
3. Performance bottlenecks.
4. Clean code & maintainability issues.

Return ONLY a valid JSON object matching this schema:
{
  "summary": "Concise 2-3 sentence executive summary of code quality and risks",
  "findings": [
    {
      "rule_id": "AI-SEC-XXX",
      "title": "Short title",
      "description": "Clear explanation of risk and impact",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "category": "security" | "bug" | "quality" | "performance" | "style",
      "line_start": 10,
      "line_end": 12,
      "suggested_fix": "Explanation of fix",
      "fix_diff": "- vulnerable_line()\\n+ secure_line()"
    }
  ]
}
Do not wrap in markdown quotes if possible, return raw valid JSON.
"""


class OpenAICompatibleProvider(BaseAIProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    @property
    def provider_name(self) -> str:
        return f"openai-{self.model}"

    async def analyze(
        self,
        code: str,
        language: str,
        static_findings: List[FindingCreate]
    ) -> Tuple[List[FindingCreate], str]:
        user_message = f"Language: {language}\n\nCode snippet:\n```{language}\n{code}\n```"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"}
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                res.raise_for_status()
                data = res.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)

                findings: List[FindingCreate] = []
                for item in parsed.get("findings", []):
                    findings.append(FindingCreate(
                        rule_id=item.get("rule_id", "AI-REV-001"),
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
                summary = parsed.get("summary", "AI review completed.")
                return findings, summary
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
