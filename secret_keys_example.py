import os

# LLM API config — uses OpenAI-compatible endpoints.
# Copy this file to secret_keys.py and fill in your API keys.
# Select provider at runtime with LLM_PROVIDER=openrouter|azure (see constants.py).

# OpenRouter
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "YOUR_API_KEY_HERE")
OPENROUTER_BASE_URL = os.environ.get(
    "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
)

# Azure (AI Foundry, OpenAI-compatible route)
AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "YOUR_AZURE_API_KEY_HERE")
AZURE_BASE_URL = os.environ.get("AZURE_BASE_URL", "")

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "tvly-api-key")
