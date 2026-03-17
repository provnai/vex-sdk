import pytest
from unittest.mock import patch, MagicMock
from provn_vex_sdk.agent import VexAgent

@pytest.mark.asyncio
async def test_binary_parity_fixed():
    # Fixed identity key and vanguard URL
    config = {
        "identity_key": "00" * 32,
        "vanguard_url": "http://localhost:3000"
    }
    agent = VexAgent(**config)
    
    # Mock time and UUID for determinism
    with patch("time.time", return_value=1710500000.0), \
         patch("uuid.uuid4", return_value="0" * 64), \
         patch("provn_sdk.ProvnSDK.sign_claim", return_value={"signature": "00" * 64}):
        
        capsule = await agent.build_capsule("test_tool", {"foo": "bar"})
        binary = agent.to_binary(capsule)
        
        with open("py_payload.hex", "w") as f:
            f.write(binary.hex())
            
        # Check header and Discovery Footer (Footer == Header)
        assert binary.startswith(b"VEP\x03")
        assert len(binary) > 152 # Header + Body + Footer
        assert binary.endswith(binary[:76]) 
