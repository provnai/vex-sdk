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
import base64
import json
import hashlib
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from provn_vex_sdk.builder import VEPBuilder, IntentSegment, AuthoritySegment, IdentitySegment, WitnessSegment

class VexAgent:
    def __init__(self, identity_key: str, vanguard_url: str = "http://localhost:3000", aid: Optional[str] = None):
        self.identity_key = identity_key
        self.vanguard_url = vanguard_url
        self.aid = aid or "00" * 32
        self.current_token = None
        self._gate_pk_cache = None

    async def fetch_public_key(self) -> str:
        """Retrieves the Gate's public key for HPKE encryption."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.vanguard_url}/public_key")
            response.raise_for_status()
            return response.json()["public_key"]

    async def verify_token(self, token_b64: str, expected_capsule_root: Optional[str] = None) -> bool:
        """Locally verifies a VEX Continuation Token (v3) against the Gate's public key."""
        import jcs
        try:
            token_json = base64.b64decode(token_b64).decode()
            token = json.loads(token_json)
            
            gate_pk_b64 = await self.fetch_public_key()
            gate_pk_bytes = base64.b64decode(gate_pk_b64)
            
            # Ed25519 Public Key from SPKI/Raw bytes
            # VEX uses raw 32-byte Ed25519 keys or SPKI. Assuming raw for now based on VEX v1.6.0.
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(gate_pk_bytes)
            except Exception:
                # Fallback to SPKI
                public_key = serialization.load_der_public_key(gate_pk_bytes)

            # 1. Re-hash payload
            payload_jcs = jcs.canonicalize(token["payload"])
            payload_hash = hashlib.sha256(payload_jcs).digest()

            # 2. Verify signature
            signature = bytes.fromhex(token["signature"])
            public_key.verify(signature, payload_hash)

            # 3. Bind to capsule root
            if expected_capsule_root and token["payload"]["source_capsule_root"] != expected_capsule_root:
                return False

            return True
        except Exception as e:
            print(f"VEX Token Verification Failed: {str(e)}")
            return False

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
            "schema": "vex/intent/v3",
            "aid": self.aid,
            "request_sha256": self._hash_object(parameters),
            "commands": [tool_name, parameters],
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
            "binding_status": "UNBOUND",
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

        witness_hash = VEPBuilder.hash_segment(witness, inclusive=False)

        # --- Phase 2: HPKE Encryption (Python) ---
        gate_pk_b64 = None
        try:
            gate_pk_b64 = await self.fetch_public_key()
        except:
            pass

        if gate_pk_b64:
            # Custom HPKE Seal (X25519-HKDF-SHA256, AES-128-GCM)
            # 1. Recipient Public Key
            recipient_pk_bytes = base64.b64decode(gate_pk_b64)
            # If it's SPKI, extract raw bytes. If raw, use directly.
            try:
                recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_pk_bytes)
            except:
                recipient_pub = serialization.load_der_public_key(recipient_pk_bytes)
                
            # 2. Ephemeral Keypair
            ephemeral_priv = x25519.X25519PrivateKey.generate()
            ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # 3. Shared Secret (DHKEM)
            shared_secret = ephemeral_priv.exchange(recipient_pub)
            
            # 4. KDF (HKDF-SHA256)
            # info = b"hpke-js" or similar context? VEX uses b"vex/intent/v3"
            info = b"vex/intent/v3"
            derived = HKDF(
                algorithm=hashes.SHA256(),
                length=12 + 16, # 12b nonce + 16b key (AES-128)
                salt=None,
                info=info
            ).derive(shared_secret)
            
            nonce = derived[:12]
            key = derived[12:]
            
            # 5. Encrypt (AES-128-GCM)
            import jcs
            plaintext = jcs.canonicalize(intent)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Intent Pillar commitment is hash of ciphertext
            intent_hash = hashlib.sha256(ciphertext).hexdigest()
            
            # Add HPKE metadata
            intent["hpke"] = {
                "enc": base64.b64encode(ephemeral_pub_bytes).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "schema": "vex/intent/v3/encrypted"
            }
        else:
            intent_hash = VEPBuilder.hash_segment(intent)

        authority_hash = VEPBuilder.hash_segment(authority)
        identity_hash = VEPBuilder.hash_segment(identity)

        capsule_root = VEPBuilder.calculate_capsule_root(
            intent_hash=intent_hash,
            authority_hash=authority_hash,
            identity_hash=identity_hash,
            witness_hash=witness_hash
        )

        # Signing (Real Ed25519 Hardware Seal)
        # Uses provn_sdk.ProvnSDK.sign_claim(claim, private_key_hex)
        sdk = provn_sdk.ProvnSDK()
        claim = {"data": capsule_root, "timestamp": int(time.time())}
        signed_claim = sdk.sign_claim(claim, self.identity_key)
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

