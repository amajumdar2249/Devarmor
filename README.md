# 🛡️ DevArmor

**One CLI command to secure your entire AI-powered developer workstation.**

As developers increasingly rely on autonomous AI agents (Claude Code, Cursor, Windsurf, Google Antigravity), our workstations are generating massive amounts of invisible "Agent Residue" — API keys dumped in chat logs, malicious MCP (Model Context Protocol) servers, and unverified AI skills. 

**DevArmor** is the first unified security scanner purpose-built for the AI-Native developer. It scans your local environment to detect leaked secrets, insecure configurations, and rogue agent remnants before they become a liability.

---

## 🚀 Features

DevArmor runs a comprehensive suite of 5 security modules in a single pass:

1. **🔑 Secret Scanner** 
   Scans your repositories and workspace for hardcoded API keys, tokens, and passwords (AWS, GitHub, OpenAI, Anthropic, Stripe, etc.).

2. **🤖 Agent Residue Scanner**
   AI agents often leak credentials into their persistent memory and conversation transcripts. This module scans `.claude`, `.cursor`, and `.gemini` directories to purge forgotten API keys embedded in chat logs.

3. **🔌 MCP Auditor**
   Model Context Protocol (MCP) servers give AI agents direct access to your local files and remote APIs. The MCP Auditor analyzes your `mcp_config.json` and `claude_desktop_config.json` to flag overly permissive tools, unverified servers, and local command execution risks.

4. **🧰 Skill Scanner**
   Analyzes agent "skills" and custom system prompts for malicious injection payloads or insecure instructions that might coerce your AI into deleting files or exfiltrating data.

5. **🛡️ Posture Checker**
   Evaluates your overall machine security posture, checking for missing permissions, insecure global NPM packages, and disabled OS firewalls.

---

## 📦 Installation & Usage

You can run DevArmor instantly via `npx` without installing it permanently:

```bash
npx devarmor scan
```

Or, install it globally:

```bash
npm install -g devarmor
devarmor scan
```

### Options

```bash
Usage: devarmor scan [options]

Options:
  --dir <path>     Directory to scan (default: current directory)
  --json           Output results in JSON format
  -h, --help       display help for command
```

---

## 📊 Example Output

```
🛡️  Starting DevArmor Security Scan...
Running modules: SecretScanner, AgentResidueScanner, MCPAuditor, SkillScanner, PostureChecker

✓ Secret Scanner completed
✓ Agent Residue Scanner completed
✓ MCP Auditor completed
✓ Skill Scanner completed
✓ Posture Checker completed

==================================================
              DEVARMOR SCAN REPORT                
==================================================

Severity Summary:
  Critical: 3
  High:     1
  Medium:   0
  Low:      2

Findings:
[CRITICAL] AgentResidueScanner
Anthropic API Key found in Claude Code chat transcript.
Path: /Users/dev/.claude/logs/transcript.jsonl
Remediation: Delete the log file and rotate the key immediately.

[HIGH] MCPAuditor
Found "npx" command execution server without sandbox boundaries.
Path: /Users/dev/.claude/claude_desktop_config.json

==================================================
```

---

## 🛠️ Development

To contribute to DevArmor or run it locally from source:

1. Clone the repository:
   ```bash
   git clone https://github.com/amajumdar2249/Devarmor.git
   cd Devarmor
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the TypeScript source:
   ```bash
   npm run build
   ```
4. Run the CLI:
   ```bash
   npm start -- scan
   ```

## 📄 License

MIT License
