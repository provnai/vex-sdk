import pytest
from provn_vex_sdk.builder import VEPBuilder

def test_calculate_capsule_root_matches_rust_vector():
    # Test hashes provided in COWORKER_HANDOFF.md.resolved (v1.5.0 Merkle Shift)
    parity_hashes = {
        "authority_hash": "6fac0de31355fc1dfe36eee1e0c226f7cc36dd58eaad0aca0c2d3873b4784d35",
        "identity_hash": "7869bae0249b33e09b881a0b44faba6ee3f4bab7edcc2aa5a5e9290e2563c828",
        "intent_hash": "e02504ea88bd9f05a744cd8a462a114dc2045eb7210ea8c6f5ff2679663c92cb",
        "witness_hash": "174dfb80917cca8a8d4760b82656e78df0778cb3aadd60b51cd018b3313d5733"
    }

    # Recalculated for 4-leaf Merkle Tree with 0x00/0x01 domain separation (Definitive v1.5.0)
    expected_root = "8acf6d45aedaf61c61142ea8f9f7a89bc90994532313f20fcc1493a95e36d405"

    calculated_root = VEPBuilder.calculate_capsule_root(
        intent_hash=parity_hashes["intent_hash"],
        authority_hash=parity_hashes["authority_hash"],
        identity_hash=parity_hashes["identity_hash"],
        witness_hash=parity_hashes["witness_hash"]
    )
    
    assert calculated_root == expected_root

def test_calculate_capsule_root_merkle_empty():
    # 4 empty 32-byte hashes
    zero_hash = "00" * 32
    root = VEPBuilder.calculate_capsule_root(zero_hash, zero_hash, zero_hash, zero_hash)
    assert root == "b46fd516fa6c7dcddd52ac2be2a014d8a8de4eaa059f79ccfcff4b8afc4e7ddc"

def test_hash_segment_canonicalization_stability():
    # Intent Pillar (Inclusive)
    intent = {
        "request_sha256": "e02504ea88bd9f05a744cd8a462a114dc2045eb7210ea8c6f5ff2679663c92cb",
        "confidence": 0.95,
        "capabilities": ["filesystem", "network"]
    }
    
    # Check that JCS stable-sorting works
    hash1 = VEPBuilder.hash_segment(intent)
    hash2 = VEPBuilder.hash_segment({
        "capabilities": ["filesystem", "network"],
        "confidence": 0.95,
        "request_sha256": "e02504ea88bd9f05a744cd8a462a114dc2045eb7210ea8c6f5ff2679663c92cb"
    })
    
    assert hash1 == hash2
