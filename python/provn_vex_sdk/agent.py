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

import httpx
import uuid
import time
import provn_sdk
from typing import Dict, Any, Optional
from provn_vex_sdk.builder import VEPBuilder, IntentSegment, AuthoritySegment, IdentitySegment, WitnessSegment

class VexAgent:
    def __init__(self, identity_key: str, vanguard_url: str = "http://localhost:3000"):
        self.identity_key = identity_key
        self.vanguard_url = vanguard_url
        self.current_token = None

    async def execute(self, tool_name: str, parameters: Dict[str, Any], intent_context: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes a tool via the VEX verifiable execution loop.
        Includes AEM (Authorization Enforcement Module) handshake and ESCALATE handling.
        """
        import asyncio
        
        # 1. Build Capsule
        capsule_data = await self.build_capsule(tool_name, parameters, intent_context)
        capsule_id = capsule_data["authority"]["capsule_id"]

        # 2. Dispatch to Vanguard
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.vanguard_url}/dispatch",
                    json=capsule_data,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                result = response.json()

                # 3. Handle AEM (ESCALATE Loop)
                attempts = 0
                max_attempts = 15 
                backoff = 1.0
                
                while result.get("outcome") == "ESCALATE" and attempts < max_attempts:
                    await asyncio.sleep(backoff)
                    attempts += 1
                    backoff = min(backoff * 1.5, 5.0) # Exponential backoff capped at 5s
                    
                    # Poll for Resolution Capsule
                    try:
                        resp = await client.get(
                            f"{self.vanguard_url}/capsule/{capsule_id}/status",
                            timeout=10.0
                        )
                        resp.raise_for_status()
                        result = resp.json()
                    except httpx.HTTPError as e:
                        print(f"[VEX] Polling error (attempt {attempts}): {str(e)}")
                        if attempts >= max_attempts:
                            raise

                if result.get("outcome") == "HALT":
                    reason = result.get('reason_code', 'UNKNOWN_REASON')
                    raise RuntimeError(f"VEX Execution HALTED by Vanguard: {reason}")
                
                if result.get("outcome") == "ESCALATE":
                    raise TimeoutError(f"VEX Escalation timed out after {attempts} attempts. Capsule ID: {capsule_id}")

                # 4. Store Capability Token
                if "capability_token" in result:
                    self.current_token = result["capability_token"]

                return result
            except Exception as e:
                print(f"VEX Transport/Gate Error: {str(e)}")
                raise

    async def build_capsule(self, tool_name: str, parameters: Dict[str, Any], intent_context: Optional[str] = None) -> Dict[str, Any]:
        """
        Manually construct a signed Evidence Capsule without dispatching it.
        """
        intent = {
            "request_sha256": self._hash_object(parameters),
            "confidence": 1.0,
            "capabilities": ["sdk_execution"]
        }
        if intent_context:
            intent["intent_context"] = intent_context

        authority = {
            "capsule_id": str(uuid.uuid4()),
            "outcome": "ALLOW",
            "reason_code": "SDK_GENERATED",
            "trace_root": "00" * 32,
            "nonce": int(time.time() * 1000),
            "prev_hash": "00" * 32, # Start of chain
            "supervision": {
                "branch_completeness": 1.0,
                "contradictions": 0,
                "confidence": 1.0
            }
        }

        identity = {
            "aid": "00" * 32,
            "identity_type": "software_sim",
            "pcrs": {"0": "00" * 32}
        }

        witness = {
            "chora_node_id": "local_witness",
            "receipt_hash": "00" * 32,
            "timestamp": int(time.time())
        }

        intent_hash = VEPBuilder.hash_segment(intent)
        authority_hash = VEPBuilder.hash_segment(authority)
        identity_hash = VEPBuilder.hash_segment(identity)
        witness_hash = VEPBuilder.hash_segment(witness, inclusive=False)

        capsule_root = VEPBuilder.calculate_capsule_root(
            intent_hash=intent_hash,
            authority_hash=authority_hash,
            identity_hash=identity_hash,
            witness_hash=witness_hash
        )

        # Signing (Real Ed25519 Hardware Seal)
        # provn_sdk.sign_claim(private_key, claim_dict)
        # It usually returns a dict with 'signature' as a hex string
        signed_claim = provn_sdk.sign_claim(self.identity_key, {"data": capsule_root, "timestamp": int(time.time())})
        signature = bytes.fromhex(signed_claim["signature"])
        import base64

        return {
            "intent": intent,
            "authority": authority,
            "identity": identity,
            "witness": witness,
            "intent_hash": intent_hash,
            "authority_hash": authority_hash,
            "identity_hash": identity_hash,
            "witness_hash": witness_hash,
            "capsule_root": capsule_root,
            "crypto": {
                "algo": "ed25519",
                "signature_scope": "capsule_root",
                "signature_b64": base64.b64encode(signature).decode(),
                "signature_raw": signature # Keep raw for binary spec
            }
        }

    def to_binary(self, capsule: Dict[str, Any]) -> bytes:
        """
        Serializes the Evidence Capsule into the v0x03 Binary Wire format.
        """
        import struct
        import jcs

        # --- Header (76 Bytes) ---
        # magic (3b), version (1b), aid (32b), root (32b), nonce (8b)
        header = b"VEP"
        header += struct.pack("B", 0x03)
        header += bytes.fromhex(capsule["identity"]["aid"])
        header += bytes.fromhex(capsule["capsule_root"])
        header += struct.pack(">Q", capsule["authority"]["nonce"])

        # --- TLV Body ---
        def pack_tlv(tag: int, data: bytes) -> bytes:
            return struct.pack(">BI", tag, len(data)) + data

        body = b""
        body += pack_tlv(0x01, jcs.canonicalize(capsule["intent"]))
        body += pack_tlv(0x02, jcs.canonicalize(capsule["authority"]))
        body += pack_tlv(0x03, jcs.canonicalize(capsule["identity"]))
        body += pack_tlv(0x05, jcs.canonicalize(capsule["witness"]))
        
        # Raw signature from build_capsule (64 bytes)
        sig = capsule["crypto"]["signature_raw"]
        body += pack_tlv(0x06, sig)

        return header + body + header

    def _hash_object(self, obj: Any) -> str:
        import jcs
        import hashlib
        canonical_json = jcs.canonicalize(obj)
        return hashlib.sha256(canonical_json).hexdigest()

