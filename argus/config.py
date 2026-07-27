from dotenv import load_dotenv
import os

# Load variables from .env
load_dotenv()


class Config:

    AI_PROVIDER = os.getenv("ARGUS_AI_PROVIDER", "none")

    # GitHub Models
    
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    GITHUB_MODEL = os.getenv(
        "GITHUB_MODEL",
        "deepseek/DeepSeek-V3-0324",
    )

    GITHUB_BASE_URL = "https://models.github.ai/inference"

    # Other providers (for future)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
    
