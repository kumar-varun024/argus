import os
import time
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, AsyncGenerator, Optional
from argus.workspace.models import Message, ImageAttachment
from argus.workspace.provider import (
    AIModelProvider,
    ProviderError,
    MockModelProvider,
    OpenAICompatibleProvider,
    GeminiProvider
)

logger = logging.getLogger("argus.workspace.provider_router")

# A 400 is a malformed request: our own bug, it would fail identically on every
# provider, so it aborts the whole chain. Every other status (auth, quota,
# model-not-found, rate-limit, 5xx, timeout) is per-provider -- the next route
# may succeed -- so it must fail over, never abort.
MALFORMED_REQUEST_STATUS: int = 400
DEAD_CREDENTIAL_STATUSES: tuple = (401, 403)

@dataclass
class ProviderRoute:
    provider_name: str
    api_base: str
    api_key: str
    model_name: str
    priority: int
    enabled: bool = True
    provider_instance: Optional[AIModelProvider] = None
    unhealthy_until: float = 0.0
    # Whether this route's model can actually accept image input. Image chat must
    # only ever be routed to vision-capable models -- failing an image request
    # over to a text-only model (e.g. nvidia nemotron) just yields a confusing
    # 400 and masks the real cause.
    supports_vision: bool = False

    def is_healthy(self) -> bool:
        return self.enabled and time.time() > self.unhealthy_until

class ProviderRouter(AIModelProvider):
    def __init__(self, routes: List[ProviderRoute], cooldown_seconds: float = 30.0):
        if not routes:
            raise ValueError("ProviderRouter requires at least one route")
        self.routes = sorted(routes, key=lambda r: r.priority)
        self.cooldown_seconds = cooldown_seconds

    def _get_healthy_routes(self) -> List[ProviderRoute]:
        return [r for r in self.routes if r.is_healthy()]

    def model_name(self) -> str:
        healthy = self._get_healthy_routes()
        if healthy:
            return f"router({healthy[0].provider_name}:{healthy[0].model_name})"
        return f"router({self.routes[0].provider_name}:{self.routes[0].model_name})"

    def capabilities(self) -> Dict[str, bool]:
        healthy = self._get_healthy_routes()
        if healthy and healthy[0].provider_instance:
            return healthy[0].provider_instance.capabilities()
        return {"vision": False, "streaming": False}

    def count_tokens(self, text: str) -> int:
        healthy = self._get_healthy_routes()
        if healthy and healthy[0].provider_instance:
            return healthy[0].provider_instance.count_tokens(text)
        return len(text.split())

    def _log_success(self, route: ProviderRoute):
        logger.info(f"provider={route.provider_name} model={route.model_name} status=success")

    def _log_failover(self, route: ProviderRoute, error: Exception):
        logger.warning(f"provider={route.provider_name} model={route.model_name} error=\"{str(error)}\" action=failover")

    def _note_route_failure(self, route: ProviderRoute, error: ProviderError) -> None:
        """Record one route's failure so the chain can fail over to the next
        route. Raises only for a universal (malformed-request) failure that
        would recur identically on every provider; every per-provider failure
        marks the route (dead credential -> disabled; anything else -> cooldown)
        and returns so the caller continues down the chain."""
        if error.status_code == MALFORMED_REQUEST_STATUS:
            logger.error(f"provider={route.provider_name} model={route.model_name} error=\"{str(error)}\" action=fatal")
            raise error
        self._log_failover(route, error)
        if error.status_code in DEAD_CREDENTIAL_STATUSES:
            route.enabled = False
        else:
            route.unhealthy_until = time.time() + self.cooldown_seconds

    def generate(self, messages: List[Message], system_prompt: str = "", **kwargs) -> str:
        last_error = None
        for route in self._get_healthy_routes():
            try:
                result = route.provider_instance.generate(messages, system_prompt=system_prompt, **kwargs)
                self._log_success(route)
                return result
            except ProviderError as e:
                self._note_route_failure(route, e)
                last_error = e
                continue
        if last_error:
            raise ProviderError(f"All providers exhausted. Last error: {last_error}", retryable=True)
        raise ProviderError("No healthy providers available", retryable=True)

    async def stream(self, messages: List[Message], system_prompt: str = "", **kwargs) -> AsyncGenerator[str, None]:
        last_error = None
        for route in self._get_healthy_routes():
            yielded = False
            try:
                async for chunk in route.provider_instance.stream(messages, system_prompt=system_prompt, **kwargs):
                    yielded = True
                    yield chunk
                self._log_success(route)
                return
            except ProviderError as e:
                if yielded:
                    logger.error(f"provider={route.provider_name} model={route.model_name} error=\"{str(e)}\" action=fatal_mid_stream")
                    raise
                self._note_route_failure(route, e)
                last_error = e
                continue
        if last_error:
            raise ProviderError(f"All providers exhausted. Last error: {last_error}", retryable=True)
        raise ProviderError("No healthy providers available", retryable=True)

    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], system_prompt: str = "", **kwargs) -> str:
        # Image requests only ever go to vision-capable routes. Every failure --
        # even a 400 -- fails over to the next vision route rather than aborting,
        # because the few vision models (e.g. Gemini) return 400/429/503 all as
        # transient throttle signals on free tiers.
        vision_routes = [r for r in self._get_healthy_routes() if r.supports_vision]
        if not vision_routes:
            raise ProviderError(
                "No vision-capable provider is available. Attach-image chat needs a "
                "vision model (e.g. Gemini, or an OpenRouter vision model via "
                "OPENROUTER_API_KEY); all configured vision routes are unhealthy or unset.",
                retryable=False,
            )
        last_error = None
        for route in vision_routes:
            try:
                result = route.provider_instance.multimodal_generate(messages, images, system_prompt=system_prompt, **kwargs)
                self._log_success(route)
                return result
            except ProviderError as e:
                self._log_failover(route, e)
                if e.status_code in DEAD_CREDENTIAL_STATUSES:
                    route.enabled = False
                else:
                    route.unhealthy_until = time.time() + self.cooldown_seconds
                last_error = e
                continue
        raise ProviderError(f"All vision providers exhausted. Last error: {last_error}", retryable=True)

def _build_openai_compatible_route(name: str, priority: int, default_base: str, default_model: str, supports_vision: bool = False) -> Optional[ProviderRoute]:
    prefix = name.upper()
    api_key = os.environ.get(f"{prefix}_API_KEY")
    if not api_key:
        return None
    api_base = os.environ.get(f"{prefix}_API_BASE", default_base)
    model = os.environ.get(f"{prefix}_MODEL_NAME", default_model)

    route = ProviderRoute(
        provider_name=name.lower(),
        api_base=api_base,
        api_key=api_key,
        model_name=model,
        priority=priority,
        supports_vision=supports_vision,
    )
    route.provider_instance = OpenAICompatibleProvider(api_base=api_base, api_key=api_key, model=model)
    return route

def _build_gemini_route(priority: int) -> Optional[ProviderRoute]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("GEMINI_MODEL_NAME", "gemini-2.5-flash")
    route = ProviderRoute(
        provider_name="gemini",
        api_base="https://generativelanguage.googleapis.com",
        api_key=api_key,
        model_name=model,
        priority=priority,
        supports_vision=True,
    )
    route.provider_instance = GeminiProvider(api_key=api_key, model=model)
    return route

def get_default_provider() -> AIModelProvider:
    if os.environ.get("ARGUS_LLM_PROVIDER", "").lower() == "mock":
        mock_route = ProviderRoute(
            provider_name="mock",
            api_base="mock",
            api_key="mock",
            model_name="mock",
            priority=1
        )
        mock_route.provider_instance = MockModelProvider()
        return ProviderRouter([mock_route])

    routes = []
    
    order_str = os.environ.get("ARGUS_PROVIDER_ORDER", "")
    primary_provider = os.environ.get("ARGUS_PRIMARY_PROVIDER", "").lower()
    primary_model = os.environ.get("ARGUS_PRIMARY_MODEL", "")

    order = [p.strip().lower() for p in order_str.split(",") if p.strip()]

    def get_priority(name: str, default_prio: int) -> int:
        if name == primary_provider:
            return 1
        if name in order:
            return 10 + order.index(name)
        return default_prio
        
    def apply_primary_model(route: ProviderRoute):
        if route.provider_name == primary_provider and primary_model:
            route.model_name = primary_model
            # Re-instantiate provider with new model
            if isinstance(route.provider_instance, OpenAICompatibleProvider):
                route.provider_instance = OpenAICompatibleProvider(
                    api_base=route.api_base, 
                    api_key=route.api_key, 
                    model=primary_model
                )
            elif isinstance(route.provider_instance, GeminiProvider):
                route.provider_instance = GeminiProvider(
                    api_key=route.api_key, 
                    model=primary_model
                )

    def _build_github_route(priority: int) -> Optional[ProviderRoute]:
        api_key = os.environ.get("GITHUB_API_KEY") or os.environ.get("GITHUB_TOKEN")
        if not api_key:
            return None
        model = os.environ.get("GITHUB_MODEL") or os.environ.get("GITHUB_MODEL_NAME", "gpt-4o")
        api_base = os.environ.get("GITHUB_API_BASE", "https://models.github.ai/inference")
        
        route = ProviderRoute(
            provider_name="github",
            api_base=api_base,
            api_key=api_key,
            model_name=model,
            priority=priority
        )
        route.provider_instance = OpenAICompatibleProvider(api_base=api_base, api_key=api_key, model=model)
        return route

    # 1. Try to build all supported providers
    github_route = _build_github_route(get_priority("github", 5))
    if github_route:
        apply_primary_model(github_route)
        routes.append(github_route)

    openai_route = _build_openai_compatible_route("openai", get_priority("openai", 10), "https://api.openai.com/v1", "gpt-4o-mini", supports_vision=True)
    if openai_route:
        apply_primary_model(openai_route)
        routes.append(openai_route)
        
    deepseek_route = _build_openai_compatible_route("deepseek", get_priority("deepseek", 20), "https://api.deepseek.com/v1", "deepseek-chat")
    if deepseek_route:
        apply_primary_model(deepseek_route)
        routes.append(deepseek_route)
        
    nvidia_route = _build_openai_compatible_route(
        "nvidia",
        get_priority("nvidia", 30),
        "https://integrate.api.nvidia.com/v1",
        "nvidia/nemotron-3.5-lightning-30b-a3b"
    )
    if nvidia_route:
        apply_primary_model(nvidia_route)
        routes.append(nvidia_route)

    nvidia_ultra_route = _build_openai_compatible_route(
        "nvidia_ultra",
        get_priority("nvidia_ultra", 31),
        "https://integrate.api.nvidia.com/v1",
        "nvidia/nemotron-3-ultra-550b-a55b"
    )
    if nvidia_ultra_route:
        apply_primary_model(nvidia_ultra_route)
        routes.append(nvidia_ultra_route)
        
    gemini_route = _build_gemini_route(get_priority("gemini", 40))
    if gemini_route:
        apply_primary_model(gemini_route)
        routes.append(gemini_route)

    # OpenRouter: an OpenAI-compatible aggregator. Its main job here is to be a
    # vision-capable FALLBACK behind Gemini (default model is a free vision
    # model), so attach-image chat still works when Gemini's free tier throttles.
    openrouter_route = _build_openai_compatible_route(
        "openrouter",
        get_priority("openrouter", 35),
        "https://openrouter.ai/api/v1",
        "google/gemma-4-31b-it:free",
        supports_vision=True,
    )
    if openrouter_route:
        apply_primary_model(openrouter_route)
        routes.append(openrouter_route)

    # Groq: free, OpenAI-compatible, very fast open-model host. Serves as the
    # fast TEXT fallback in place of NVIDIA's endpoint (whose serverless models
    # are unprovisioned / capacity-exhausted / time out for most accounts).
    groq_route = _build_openai_compatible_route(
        "groq",
        get_priority("groq", 15),
        "https://api.groq.com/openai/v1",
        # Groq's current production flagship (MoE 120B, ~500 tok/s, 131k ctx).
        # Groq deprecated llama-3.3-70b-versatile / llama-3.1-8b-instant in
        # 2026-06 and recommends gpt-oss-120b as the migration target.
        "openai/gpt-oss-120b",
    )
    if groq_route:
        apply_primary_model(groq_route)
        routes.append(groq_route)

    # Generic Local / Custom OpenAI Compatible
    local_route = _build_openai_compatible_route("local", get_priority("local", 50), "http://localhost:8000/v1", "local-model")
    if local_route:
        apply_primary_model(local_route)
        routes.append(local_route)
        
    if not routes:
        logger.warning("No valid provider configurations found. Falling back to MockModelProvider.")
        mock_route = ProviderRoute(
            provider_name="mock",
            api_base="mock",
            api_key="mock",
            model_name="mock",
            priority=100
        )
        mock_route.provider_instance = MockModelProvider()
        routes.append(mock_route)
        
    return ProviderRouter(routes)
