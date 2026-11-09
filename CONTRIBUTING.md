# Contributing to Mythos Agent

Thank you for your interest in contributing to Mythos Agent! Whether you are fixing bugs, writing tests, improving documentation, or adding support for new LLM providers and security checks, your contributions are welcome.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. **Fork and Clone**
   ```bash
   git clone https://github.com/<your-username>/0707.git
   cd 0707
   ```

2. **Install Dependencies**
   ```bash
   npm ci
   ```

3. **Run the Test Suite**
   Ensure existing tests pass before making changes:
   ```bash
   npm test
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```

2. Make targeted, atomic changes. Adhere to existing coding style and conventions.

3. Add unit tests for your changes under `test/`.

4. Run linting and test passes:
   ```bash
   npm test
   ```

5. Commit changes using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add support for local Ollama provider`
   - `fix: prevent scope violation during DNS resolution`
   - `docs: update MCP server configuration guide`
   - `test: add tests for report generator markdown formatting`

6. Push your branch and open a Pull Request against `main`.

## Pull Request Guidelines

- Ensure your PR title follows Conventional Commits.
- Fill out all sections in the [PR template](.github/PULL_REQUEST_TEMPLATE.md).
- Ensure all CI tests pass.
- Address review comments promptly.
