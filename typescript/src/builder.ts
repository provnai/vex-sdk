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

export interface IntentSegment {
    request_sha256: string;
    confidence: number;
    capabilities: string[];
    magpie_source?: string;
}

export interface AuthoritySegment {
    capsule_id: string;
    outcome: 'ALLOW' | 'HALT' | 'ESCALATE';
    reason_code: string;
    trace_root: string;
    nonce: number;
    prev_hash?: string;       // VEX Ledger Link
    supervision?: {           // MCS Signals
        branch_completeness?: number;
        contradictions?: number;
        confidence?: number;
    };
    gate_sensors?: Record<string, any>;
}

export interface IdentitySegment {
    aid: string;
    identity_type: string;
    pcrs: Record<string, string>;
}

export interface WitnessSegment {
    chora_node_id: string;
    receipt_hash: string;
    timestamp: number;
}

export interface VexPillars {
    intent: IntentSegment;
    authority: AuthoritySegment;
    identity: IdentitySegment;
    witness: WitnessSegment;
}

export class VEPBuilder {
    /**
     * Computes the SHA-256 hash of a JCS canonicalized object.
     */
    static hashSegment(segment: any, inclusive: boolean = true): string {
        let dataToHash = segment;
        
        if (!inclusive) {
            // Witness pillar uses Minimal scope (Explicit fields only, EXCLUDING receipt_hash)
            const minimal = {
                chora_node_id: segment.chora_node_id,
                timestamp: segment.timestamp
            };
            dataToHash = minimal;
        }

        const canonicalJSON = canonicalize(dataToHash);
        return crypto.createHash('sha256').update(canonicalJSON).digest('hex');
    }

    /**
     * Calculates the capsule_root commitment using a 4-leaf binary Merkle tree
     * with domain separation (0x00 for leaves, 0x01 for internal nodes).
     * Pillar Order: Intent, Authority, Identity, Witness.
     */
    static calculateCapsuleRoot(hashes: {
        intent_hash: string;
        authority_hash: string;
        identity_hash: string;
        witness_hash: string;
    }): string {
        const hashLeaf = (data_hex: string) => {
            const leaf = Buffer.concat([Buffer.from([0x00]), Buffer.from(data_hex, 'hex')]);
            return crypto.createHash('sha256').update(leaf).digest();
        };

        const hashInternal = (left: Buffer, right: Buffer) => {
            const internal = Buffer.concat([Buffer.from([0x01]), left, right]);
            return crypto.createHash('sha256').update(internal).digest();
        };

        // 1. Leaf Hashes
        const hi = hashLeaf(hashes.intent_hash);
        const ha = hashLeaf(hashes.authority_hash);
        const hid = hashLeaf(hashes.identity_hash);
        const hw = hashLeaf(hashes.witness_hash);

        // 2. Layer 1 (Internal Nodes)
        const h12 = hashInternal(hi, ha);
        const h34 = hashInternal(hid, hw);

        // 3. Root
        const rootDigest = hashInternal(h12, h34);
        return rootDigest.toString('hex');
    }
}

