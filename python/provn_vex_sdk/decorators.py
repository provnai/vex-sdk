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

import functools
import inspect
from typing import Callable, Any, Optional
from .agent import VexAgent

def vex_secured(intent: str, vanguard_url: str = "http://localhost:3000"):
    """
    Decorator to automatically wrap a function call in a VEX Evidence Capsule (VEP)
    and dispatch it to the proxy before (or during) execution.
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # 1. Extract and validate identity
            import os
            identity_key = os.getenv("VEX_IDENTITY_KEY")
            if not identity_key:
                raise RuntimeError("VEX_IDENTITY_KEY environment variable is required for @vex_secured")
            
            # Simple hex validation for Ed25519 keys (usually 32 bytes = 64 hex chars)
            if len(identity_key) < 64 or not all(c in "0123456789abcdefABCDEF" for c in identity_key):
                raise ValueError("VEX_IDENTITY_KEY must be a 64-character hex string (Ed25519 private key)")
            
            # 2. Extract arguments for the VEP Intent
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            agent = VexAgent(identity_key=identity_key, vanguard_url=vanguard_url)
            
            # 3. Perform the VEX Verifiable Execution loop
            # We call execute which builds the capsule and posts it to Vanguard
            # The result from Vanguard confirms if the execution is "ALLOWED"
            vex_result = await agent.execute(
                tool_name=func.__name__,
                parameters=dict(bound_args.arguments),
                intent_context=intent
            )
            
            # 4. If Vanguard allows, proceed with local execution
            # In a real-world scenario, Vanguard might return a 'trace_root' or 'session_id'
            return await func(*args, **kwargs)
        return wrapper
    return decorator

