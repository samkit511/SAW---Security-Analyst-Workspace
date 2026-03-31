import os

try:
    from google import genai
except ImportError:
    genai = None

GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("ASA_REMEDIATION_MODEL", "gemini-2.5-flash")

if genai is not None and GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None


def generate_remediation(threat_type: str, signal: str = "") -> str:
    """Uses the Google GenAI SDK for remediation guidance."""
    prompt = (
        f"Remediate security threat: {threat_type}. "
        f"Context: {signal}. Provide concise secure remediation guidance and, when helpful, a code example."
    )

    try:
        if client is None:
            raise RuntimeError("Gemini remediation client unavailable")
        response = client.models.generate_content(model=MODEL_NAME, contents=prompt)
        return response.text or "Recommendation: Parameterize queries and escape all user inputs."
    except Exception:
        return "Recommendation: Parameterize queries and escape all user inputs."
