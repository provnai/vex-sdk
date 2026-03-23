/**
 * Copyright 2026 ProvnAI
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as crypto from 'crypto';
const { canonicalize } = require('json-canonicalize');
import axios from 'axios';
import { VEPBuilder, VexCapsule, IntentSegment, AuthoritySegment } from './builder';
import { ProvnSDK, init } from '@provncloud/sdk';
const { CipherSuite } = require('hpke-js');
const { DhkemX25519HkdfSha256, HkdfSha256 } = require('@hpke/dhkem-x25519');
const { Aes128Gcm } = require('@hpke/core');

export interface VexConfig {
    identityKey: string;     // Hex or Base64 Ed25519 private key
    vanguardUrl: string;     // Target proxy endpoint (McpVanguard/VEX sidecar)
    aid?: string;            // Agent Identity ID (NEW in v3)
}

export interface VexResult {
    status: string;
    outcome: 'ALLOW' | 'HALT' | 'ESCALATE';
    reason_code?: string;
    capsule_root: string;
    capability_token?: string;
    [key: string]: unknown;
}

export class VexAgent {
    private config: VexConfig;
    private sdk: ProvnSDK | null = null;

    private currentToken?: string;

    constructor(config: VexConfig) {
        this.config = config;
    }

    private async ensureSDK() {
        if (!this.sdk) {
            await init();
            this.sdk = new ProvnSDK();
        }
    }

    /**
     * Retrieves the Gate's public key for HPKE encryption.
     */
    async fetchPublicKey(): Promise<string> {
        const response = await axios.get(`${this.config.vanguardUrl}/public_key`);
        return response.data.public_key;
    }

    /**
     * Executes a tool via the VEX verifiable execution loop.
     */
    /**
     * Locally verifies a VEX Continuation Token (v3) against the Gate's public key.
     * Ensures the token was signed by the authoritative Gate and binds to the current capsule.
     */
    async verifyToken(tokenBase64: string, expectedCapsuleRoot?: string): Promise<boolean> {
        const { canonicalize } = require('json-canonicalize');
        const crypto = require('crypto');
        
        try {
            const token = JSON.parse(Buffer.from(tokenBase64, 'base64').toString());
            const gatePkBase64 = await this.fetchPublicKey();
            const gatePublicKey = crypto.createPublicKey({
                key: Buffer.from(gatePkBase64, 'base64'),
                format: 'der',
                type: 'spki', // Ed25519 in SPKI format
            });

            // 1. Re-hash the payload (JCS)
            const payloadHash = crypto.createHash('sha256')
                .update(canonicalize(token.payload))
                .digest();

            // 2. Verify signature
            const isSignatureValid = crypto.verify(
                null,
                payloadHash,
                gatePublicKey,
                Buffer.from(token.signature, 'hex')
            );

            if (!isSignatureValid) {
                console.error('VEX Token Verification Failed: Invalid Signature');
                return false;
            }

            // 3. Bind to capsule root
            if (expectedCapsuleRoot && token.payload.source_capsule_root !== expectedCapsuleRoot) {
                console.error('VEX Token Verification Failed: Root Mismatch');
                return false;
            }

            return true;
        } catch (error) {
            console.error('VEX Token Verification Error:', error);
            return false;
        }
    }

    async execute(toolName: string, params: Record<string, unknown>, intentContext?: string): Promise<VexResult> {
        await this.ensureSDK();

        // 1. Build Capsule
        const capsuleData = await this.buildCapsule(toolName, params, intentContext);
        const capsuleId = capsuleData.authority.capsule_id;

        // 2. Dispatch to Vanguard
        try {
            const response = await axios.post(`${this.config.vanguardUrl}/dispatch`, capsuleData, {
                headers: { 'Content-Type': 'application/json' }
            });
            let result = response.data;

            // 3. Handle AEM (ESCALATE Loop)
            let attempts = 0;
            const maxAttempts = 15; // ~30 seconds

            while (result.outcome === 'ESCALATE' && attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 2000));
                attempts++;

                const pollResp = await axios.get(`${this.config.vanguardUrl}/capsule/${capsuleId}/status`, {
                    headers: { 'Accept': 'application/json' }
                });
                result = pollResp.data;
            }

            if (result.outcome === 'HALT') {
                throw new Error(`VEX Execution HALTED: ${result.reason_code}`);
            }

            if (result.outcome === 'ESCALATE') {
                throw new Error('VEX Escalated resolution timed out.');
            }

            // 4. Store Capability Token
            if (result.capability_token) {
                this.currentToken = result.capability_token;
            }

            return result as VexResult;
        } catch (error) {
            const err = error as { response?: { data: Record<string, unknown> }, message: string };
            console.error('VEX Execution Failed:', err.response?.data || err.message);
            throw error;
        }
    }

    /**
     * Manually construct a signed Evidence Capsule without dispatching it.
     */
    async buildCapsule(toolName: string, params: Record<string, unknown>, intentContext?: string): Promise<VexCapsule> {
        await this.ensureSDK();
        // This is a simplified implementation for the SDK.
        // It demonstrates how the builder is leveraged.
        
        const intent: IntentSegment = {
            schema: 'vex/intent/v3',
            aid: this.config.aid || '00'.repeat(32),
            request_sha256: this.hashObject(params),
            commands: [toolName, params],
            confidence: 1.0,
            capabilities: ['sdk_execution']
        };
        if (intentContext) {
            intent.intent_context = intentContext;
        }

        const authority: AuthoritySegment = {
            capsule_id: require('crypto').randomUUID(),
            outcome: 'ALLOW',
            reason_code: 'SDK_GENERATED',
            trace_root: '00'.repeat(32),
            nonce: Date.now(),
            prev_hash: '00'.repeat(32), // Start of chain
            binding_status: 'UNBOUND',
            supervision: {
                branch_completeness: 1.0,
                contradictions: 0,
                confidence: 1.0
            }
        };

        const identity = {
            aid: this.config.aid || '00'.repeat(32),
            identity_type: 'software_sim',
            pcrs: { '0': '00'.repeat(32) }
        };

        const witness = {
            chora_node_id: 'local_witness',
            receipt_hash: '00'.repeat(32),
            timestamp: Math.floor(Date.now() / 1000)
        };

        // --- Phase 2: HPKE Encryption (Optional/v3) ---
        let intent_hash: string;
        const gatePkBase64 = await this.fetchPublicKey().catch(() => null);
        
        if (gatePkBase64) {
            const suite = new CipherSuite({
                kem: new DhkemX25519HkdfSha256(),
                kdf: new HkdfSha256(),
                aead: new Aes128Gcm(),
            });

            const recipientPublicKeyRaw = new Uint8Array(Buffer.from(gatePkBase64, 'base64'));
            const recipientKey = await suite.importKey('raw', recipientPublicKeyRaw, true);
            const info = new Uint8Array(Buffer.from('vex/intent/v3'));
            
            const { enc, ct } = await suite.seal(
                { 
                    recipientPublicKey: recipientKey,
                    info: info
                },
                new Uint8Array(Buffer.from(JSON.stringify(intent)))
            );

            // In v1.6.0, the "Intent Pillar" commitment is the hash of the ciphertext
            intent_hash = require('crypto').createHash('sha256').update(Buffer.from(ct)).digest('hex');
            
            // Add HPKE metadata to the segment so the Gate can decrypt
            intent.hpke = {
                enc: Buffer.from(enc).toString('base64'),
                ciphertext: Buffer.from(ct).toString('base64'),
                schema: 'vex/intent/v3/encrypted'
            };
        } else {
            // Fallback: Standard JCS hash for Transparent intents
            intent_hash = VEPBuilder.hashSegment(intent);
        }

        const authority_hash = VEPBuilder.hashSegment(authority);
        const identity_hash = VEPBuilder.hashSegment(identity);
        const witness_hash = VEPBuilder.hashSegment(witness, false); // Minimal scope

        const capsule_root = VEPBuilder.calculateCapsuleRoot({
            intent_hash,
            authority_hash,
            identity_hash,
            witness_hash
        });

        // Sign the capsule_root
        const claim = this.sdk!.createClaimNow(capsule_root);
        const keyPair = { 
            private_key: this.config.identityKey, 
            public_key: '00'.repeat(32) // In real use, this comes from the config/key derivation
        };
        this.sdk!.setKeypair(keyPair);
        const signedClaim = this.sdk!.signClaim(claim);
        const signature = Buffer.from(signedClaim.signature, 'hex');

        return {
            intent,
            authority,
            identity,
            witness,
            intent_hash,
            authority_hash,
            identity_hash,
            witness_hash,
            capsule_root,
            crypto: {
                algo: 'ed25519',
                signature_scope: 'capsule_root',
                signature_b64: signature.toString('base64'),
                signature_raw: signature // Keep raw for binary spec
            }
        };
    }

    /**
     * Serializes the Evidence Capsule into the v0x03 Binary Wire format.
     */
    toBinary(capsule: VexCapsule): Buffer {
        const { canonicalize } = require('json-canonicalize');
        
        // --- Header (76 Bytes) ---
        const header = Buffer.alloc(76);
        header.write('VEP', 0);
        header.writeUInt8(0x03, 3);
        header.write(capsule.identity.aid.replace(/-/g, ''), 4, 'hex'); // Ensure hex
        header.write(capsule.capsule_root, 36, 'hex');
        header.writeBigUInt64BE(BigInt(capsule.authority.nonce), 68);

        // --- TLV Body ---
        const packTLV = (tag: number, data: Buffer) => {
            const tlv = Buffer.alloc(5 + data.length);
            tlv.writeUInt8(tag, 0);
            tlv.writeUInt32BE(data.length, 1);
            data.copy(tlv, 5);
            return tlv;
        };

        const segments = [
            packTLV(0x01, Buffer.from(canonicalize(capsule.intent))),
            packTLV(0x02, Buffer.from(canonicalize(capsule.authority))),
            packTLV(0x03, Buffer.from(canonicalize(capsule.identity))),
            packTLV(0x05, Buffer.from(canonicalize(capsule.witness))),
            packTLV(0x06, capsule.crypto.signature_raw)
        ];

        return Buffer.concat([header, ...segments, header]);
    }

    private hashObject(obj: Record<string, unknown>): string {
        const canonicalJSON = canonicalize(obj);
        return crypto.createHash('sha256').update(canonicalJSON).digest('hex');
    }
}

