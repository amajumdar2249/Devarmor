# DevArmor

**One CLI command to secure your entire AI-powered developer workstation.**

DevArmor is an integrated security scanner built specifically for modern developer workflows involving autonomous AI agents, Local LLMs, and Model Context Protocol (MCP) integrations. It identifies secrets, agent residue, overly permissive skills, and workstation misconfigurations.

## Installation

```bash
npm install -g devarmor
```

## Features

- **SecretScanner**: Detects hardcoded API keys, tokens, and credentials.
- **AgentResidueScanner**: Finds leftover artifacts from AI agent sessions.
- **MCPAuditor**: Analyzes your MCP configuration for security risks.
- **SkillScanner**: Inspects agent skills for dangerous permissions.
- **PostureChecker**: Validates your overall workstation security posture.

## Usage

Run a full security scan on your current directory:
```bash
devarmor scan .
```

Generate an HTML report:
```bash
devarmor scan . --report html
```

## License

MIT
