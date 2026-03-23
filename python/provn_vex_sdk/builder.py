# Copyright 2026 ProvnAI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import jcs
import struct
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field

class IntentSegment(BaseModel):
    schema_v: str = Field(default="vex/intent/v3", alias="schema")
    aid: str
    request_sha256: str
    commands: List[Any]
    confidence: float
    capabilities: List[str]
    magpie_source: Optional[str] = None
    model_config = {"extra": "forbid"}

class AuthoritySegment(BaseModel):
    capsule_id: str
    outcome: str # ALLOW | HALT | ESCALATE
    reason_code: str
    trace_root: str
    nonce: int
    prev_hash: Optional[str] = "00" * 32 # VEX Ledger Link
    binding_status: str = "UNBOUND"
    continuation_token: Optional[Dict[str, Any]] = None
    supervision: Optional[Dict[str, Any]] = Field(default_factory=dict) # MCS Signals
    gate_sensors: Optional[Dict[str, Any]] = None
    model_config = {"extra": "forbid"}

class IdentitySegment(BaseModel):
    aid: str
    identity_type: str
    pcrs: Dict[str, str]
    model_config = {"extra": "forbid"}

class WitnessSegment(BaseModel):
    chora_node_id: str
    receipt_hash: str
    timestamp: int
    model_config = {"extra": "forbid"}

class VEPBuilder:
    @staticmethod
    def hash_segment(segment: Union[BaseModel, Dict[str, Any]], inclusive: bool = True) -> str:
        """
        Computes the SHA-256 hash of a JCS canonicalized object.
        """
        if isinstance(segment, BaseModel):
            data_to_hash = segment.model_dump(exclude_none=True)
        else:
            data_to_hash = segment

        if not inclusive:
            # Witness pillar uses Minimal scope (Explicit fields only, EXCLUDING receipt_hash)
            minimal = {
                "chora_node_id": segment.get("chora_node_id"),
                "timestamp": segment.get("timestamp")
            }
            data_to_hash = minimal

        canonical_json = jcs.canonicalize(data_to_hash)
        return hashlib.sha256(canonical_json).hexdigest()

    @staticmethod
    def calculate_capsule_root(
        intent_hash: str,
        authority_hash: str,
        identity_hash: str,
        witness_hash: str
    ) -> str:
        """
        Calculates the capsule_root commitment using a 4-leaf binary Merkle tree
        with domain separation (0x00 for leaves, 0x01 for internal nodes).
        Pillar Order: Intent, Authority, Identity, Witness.
        """
        def hash_leaf(data_hex: str) -> bytes:
            return hashlib.sha256(b"\x00" + bytes.fromhex(data_hex)).digest()

        def hash_internal(left: bytes, right: bytes) -> bytes:
            return hashlib.sha256(b"\x01" + left + right).digest()

        # 1. Leaf Hashes
        hi = hash_leaf(intent_hash)
        ha = hash_leaf(authority_hash)
        hid = hash_leaf(identity_hash)
        hw = hash_leaf(witness_hash)

        # 2. Layer 1 (Internal Nodes)
        h12 = hash_internal(hi, ha)
        h34 = hash_internal(hid, hw)

        # 3. Root
        root_digest = hash_internal(h12, h34)
        return root_digest.hex()
