import pytest
from provn_vex_sdk.builder import VEPBuilder

def test_calculate_capsule_root_matches_rust_vector():
    # Test hashes recalculated for v1.6.0 Protocol Alignment
    parity_hashes = {
        "authority_hash": "1f66eab08c7276b5bd65b6624193eb216159a675e43b85d827de85ec065495c6",
        "identity_hash": "7869bae0249b33e09b881a0b44faba6ee3f4bab7edcc2aa5a5e9290e2563c828",
        "intent_hash": "ce4041d35af4dd0c00b60a04c80779516178097f7ab7e20fea6da2996dc06446",
        "witness_hash": "2aa5ae39acd791e6ae12341b4e82ec16cfcdd2ab4e46a8fb48389dff6217fd42"
    }

    expected_root = "35ef4684c3168f54f040e0e6a24d5bde35464731e6c32bb34bcc30fbb69c8255"

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
        "schema": "vex/intent/v3",
        "aid": "00" * 32,
        "request_sha256": "ce4041d35af4dd0c00b60a04c80779516178097f7ab7e20fea6da2996dc06446",
        "commands": ["test_tool", {"foo": "bar"}],
        "confidence": 1.0,
        "capabilities": ["sdk_execution"]
    }
    
    # Check that JCS stable-sorting works
    hash1 = VEPBuilder.hash_segment(intent)
    hash2 = VEPBuilder.hash_segment({
        "capabilities": ["sdk_execution"],
        "confidence": 1.0,
        "commands": ["test_tool", {"foo": "bar"}],
        "request_sha256": "ce4041d35af4dd0c00b60a04c80779516178097f7ab7e20fea6da2996dc06446",
        "aid": "00" * 32,
        "schema": "vex/intent/v3"
    })
    
    assert hash1 == hash2
