import pytest
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

# Mock missing modules to allow collection without full environment
mock_modules = [
    "motor", "motor.motor_asyncio", "pymongo", "chromadb", 
    "sentence_transformers", "guardrails", "lmql", "datasets",
    "transformers", "torch"
]
for mod in mock_modules:
    sys.modules[mod] = MagicMock()

from app.proxy.llm_proxy import LLMProxy, ProxyError

@pytest.mark.asyncio
async def test_route_request_provider_selection():
    proxy = LLMProxy()
    
    # Mock keys: only Gemini and OpenAI are available
    async def mock_get_key(p):
        if p == "gemini": return "g-key"
        if p == "openai": return "o-key"
        return ""
    
    with patch.object(proxy, '_get_provider_key', side_effect=mock_get_key):
        proxy._call_gemini = AsyncMock(return_value=MagicMock(text="gemini response", provider="gemini", request_id="1"))
        proxy._call_openai = AsyncMock(return_value=MagicMock(text="openai response", provider="openai", request_id="2"))
        proxy._call_anthropic = AsyncMock()
        proxy._call_mistral = AsyncMock()
        
        # 1. Test "gemini" explicit
        res = await proxy.route_request(provider="gemini", prompt="hello")
        assert res.text == "gemini response"
        proxy._call_gemini.assert_called()
        
        # 2. Test "openai" explicit
        res = await proxy.route_request(provider="openai", prompt="hello")
        assert res.text == "openai response"
        proxy._call_openai.assert_called()
        
        # 3. Test "mistral" (not available) -> should auto-route to first available (gemini)
        proxy._call_gemini.reset_mock()
        res = await proxy.route_request(provider="mistral", prompt="hello")
        assert res.text == "gemini response"
        proxy._call_gemini.assert_called()

@pytest.mark.asyncio
async def test_fallback_logic():
    proxy = LLMProxy()
    
    # Mock keys: Gemini and Mistral available
    async def mock_get_key(p):
        if p == "gemini": return "g-key"
        if p == "mistral": return "m-key"
        return ""
    
    with patch.object(proxy, '_get_provider_key', side_effect=mock_get_key):
        # Primary (gemini) fails with transient error
        proxy._call_gemini = AsyncMock(return_value=ProxyError(code=500, message="Fail", request_id="1"))
        # Fallback (mistral) succeeds
        proxy._call_mistral = AsyncMock(return_value=MagicMock(text="mistral fallback", provider="mistral", request_id="2"))
        
        res = await proxy.route_request(provider="auto", prompt="hello")
        
        assert res.text == "mistral fallback"
        proxy._call_gemini.assert_called()
        proxy._call_mistral.assert_called()

@pytest.mark.asyncio
async def test_simulation_mode_no_keys():
    proxy = LLMProxy()
    
    # No keys available
    with patch.object(proxy, '_get_provider_key', return_value=""):
        res = await proxy.route_request(provider="auto", prompt="hello")
        assert "SIMULATION MODE" in res.text
        assert "Google Gemini" in res.text
        assert "Mistral AI" in res.text
        assert "OpenAI" in res.text
        assert "Anthropic" in res.text
