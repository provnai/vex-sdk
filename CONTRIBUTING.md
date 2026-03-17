# Contributing to VEX SDK 🤝

First off, thanks for taking the time to contribute! We're building the future of verifiable AI, and we'd love for you to be part of it.

## 🌈 Our Philosophy

We value:
1. **Simplicity:** Code should be easy to read and documentation should be down-to-earth.
2. **Security:** Every line of code should be auditable.
3. **Parity:** Changes must happen in both Python and TypeScript to keep our hashes synchronized.

## 🚀 Getting Started

1. **Fork the repo** and create your branch from `main`.
2. **Install dependencies**:
   - Python: `cd python && pip install -e .[test]`
   - TypeScript: `cd typescript && npm install`
3. **Make your changes**. 
4. **Run the tests** (this is critical!):
   - Python: `pytest`
   - TypeScript: `npm test`
5. **Update both SDKs**. If you change a hashing algorithm, you MUST update both languages and ensure the binary parity tests pass.

## 📬 Pull Request Process

1. Update the README.md if yours is a user-facing change.
2. Ensure all tests pass.
3. We'll review your PR and merge it once it satisfies the "VEX Security Bar."

---

Happy coding! 🛡️⚓🚀
