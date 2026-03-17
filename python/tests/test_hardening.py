import pytest
from provn_vex_sdk.builder import IntentSegment
from pydantic import ValidationError

def test_schema_hardening_forbids_extra_fields():
    # Attempting to create a segment with an extra field should raise ValidationError
    with pytest.raises(ValidationError):
        IntentSegment(
            request_sha256="00" * 32,
            confidence=1.0,
            capabilities=["test"],
            extra_malicious_field="should fail"
        )

def test_witness_pillar_minimal_scope():
    from provn_vex_sdk.builder import VEPBuilder
    
    witness_a = {
        "chora_node_id": "tester",
        "receipt_hash": "01" * 32,
        "timestamp": 12345678
    }
    
    witness_b = {
        "chora_node_id": "tester",
        "receipt_hash": "ff" * 32, # Different receipt_hash
        "timestamp": 12345678
    }
    
    # Hashing with inclusive=False should ignore receipt_hash
    hash_a = VEPBuilder.hash_segment(witness_a, inclusive=False)
    hash_b = VEPBuilder.hash_segment(witness_b, inclusive=False)
    
    assert hash_a == hash_b
