import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from provn_vex_sdk.agent import VexAgent

@pytest.mark.asyncio
async def test_execute_constructs_capsule_and_sends_post():
    config = {
        "identity_key": "fake_key",
        "vanguard_url": "http://localhost:3000"
    }
    agent = VexAgent(**config)
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "verified"}
    mock_response.raise_for_status = lambda: None
    
    signed_claim_mock = {"signature": "00" * 64}
    
    # Patch the AsyncClient class to control its behavior as a context manager
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
         patch("provn_sdk.sign_claim", return_value=signed_claim_mock):
        mock_post.return_value = mock_response
        
        result = await agent.execute("test_tool", {"foo": "bar"})
        
        assert result["status"] == "verified"
        assert mock_post.called

@pytest.mark.asyncio
async def test_build_capsule_async():
    config = {
        "identity_key": "fake_key",
        "vanguard_url": "http://localhost:3000"
    }
    agent = VexAgent(**config)
    
    signed_claim_mock = {"signature": "00" * 64}
    with patch("provn_sdk.sign_claim", return_value=signed_claim_mock):
        capsule = await agent.build_capsule("test", {"foo": "bar"})
        assert "capsule_root" in capsule
        assert "crypto" in capsule
        assert capsule["crypto"]["signature_b64"] is not None
