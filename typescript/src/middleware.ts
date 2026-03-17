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

import { VexAgent } from './agent';

/**
 * Vercel AI SDK compatible middleware for VEX-secured tool execution.
 */
export const vexMiddleware = (config: { identityKey: string, vanguardUrl: string }) => {
    const agent = new VexAgent(config);

    return {
        // This is a pattern used by Vercel AI SDK to intercept tool calls
        async onToolCall({ toolName, args }: { toolName: string, args: any }) {
            console.log(`[VEX] Securing tool call: ${toolName}`);
            
            try {
                const result = await agent.execute(toolName, args, `Vercel AI SDK forced verification for ${toolName}`);
                
                // If execute doesn't throw, it means Vanguard/VEX sidecar allowed it
                return {
                    status: 'verified',
                    vex_root: result.capsule_root
                };
            } catch (error) {
                console.error(`[VEX] Blocked tool execution: ${toolName}`);
                throw new Error(
                    `VEX Verification Failed: ${toolName} execution not authorized. Reason: ${error instanceof Error ? error.message : String(error)}`
                );
            }
        }
    };
};

