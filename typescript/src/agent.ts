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

import axios from 'axios';
import { VEPBuilder, VexPillars } from './builder';
import { ProvnSDK, init } from '@provncloud/sdk';

export interface VexConfig {
    identityKey: string;     // Hex or Base64 Ed25519 private key
    vanguardUrl: string;     // Target proxy endpoint (McpVanguard/VEX sidecar)
}

export class VexAgent {
    private config: VexConfig;
    private sdk: ProvnSDK | null = null;

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
     * Executes a tool via the VEX verifiable execution loop.
     */
    async execute(toolName: string, params: Record<string, any>, intentContext?: string): Promise<any> {
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
                throw new Error("VEX Escalated resolution timed out.");
            }

            // 4. Store Capability Token
            if (result.capability_token) {
                (this as any).currentToken = result.capability_token;
            }

            return result;
        } catch (error: any) {
            console.error('VEX Execution Failed:', error.response?.data || error.message);
            throw error;
        }
    }

    /**
     * Manually construct a signed Evidence Capsule without dispatching it.
     */
    async buildCapsule(toolName: string, params: Record<string, any>, intentContext?: string): Promise<any> {
        await this.ensureSDK();
        // This is a simplified implementation for the SDK.
        // It demonstrates how the builder is leveraged.
        
        const intent: any = {
            request_sha256: this.hashObject(params),
            confidence: 1.0,
            capabilities: ["sdk_execution"]
        };
        if (intentContext) {
            intent.intent_context = intentContext;
        }

        const authority = {
            capsule_id: require('crypto').randomUUID(),
            outcome: 'ALLOW',
            reason_code: 'SDK_GENERATED',
            trace_root: "00".repeat(32),
            nonce: Date.now(),
            prev_hash: "00".repeat(32), // Start of chain
            supervision: {
                branch_completeness: 1.0,
                contradictions: 0,
                confidence: 1.0
            }
        };

        const identity = {
            aid: "00".repeat(32), // Placeholder for hardware AID
            identity_type: "software_sim",
            pcrs: { "0": "00".repeat(32) }
        };

        const witness = {
            chora_node_id: "local_witness",
            receipt_hash: "00".repeat(32),
            timestamp: Math.floor(Date.now() / 1000)
        };

        const intent_hash = VEPBuilder.hashSegment(intent);
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
            public_key: "00".repeat(32) // In real use, this comes from the config/key derivation
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
                algo: "ed25519",
                signature_scope: "capsule_root",
                signature_b64: signature.toString('base64'),
                signature_raw: signature // Keep raw for binary spec
            }
        };
    }

    /**
     * Serializes the Evidence Capsule into the v0x03 Binary Wire format.
     */
    toBinary(capsule: any): Buffer {
        const { canonicalize } = require('json-canonicalize');
        
        // --- Header (76 Bytes) ---
        const header = Buffer.alloc(76);
        header.write("VEP", 0);
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

    private hashObject(obj: any): string {
        const { canonicalize } = require('json-canonicalize');
        const crypto = require('crypto');
        const canonicalJSON = canonicalize(obj);
        return crypto.createHash('sha256').update(canonicalJSON).digest('hex');
    }
}

