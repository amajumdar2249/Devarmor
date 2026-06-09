import { SecretScanner } from '../src/modules/secret-scanner';
import { AgentResidueScanner } from '../src/modules/agent-residue';
import { MCPAuditor } from '../src/modules/mcp-auditor';
import { SkillScanner } from '../src/modules/skill-scanner';
import { PostureChecker } from '../src/modules/posture-checker';

describe('DevArmor Scanner Modules', () => {
  it('should instantiate SecretScanner with correct name and label', () => {
    const scanner = new SecretScanner();
    expect(scanner.name).toBe('SecretScanner');
    expect(scanner.label).toBe('🔑 Secret Scanner');
    expect(typeof scanner.scan).toBe('function');
  });

  it('should instantiate AgentResidueScanner with correct name and label', () => {
    const scanner = new AgentResidueScanner();
    expect(scanner.name).toBe('AgentResidueScanner');
    expect(scanner.label).toBe('🤖 Agent Residue Scanner');
    expect(typeof scanner.scan).toBe('function');
  });

  it('should instantiate MCPAuditor with correct name and label', () => {
    const scanner = new MCPAuditor();
    expect(scanner.name).toBe('MCPAuditor');
    expect(scanner.label).toBe('📡 MCP Auditor');
    expect(typeof scanner.scan).toBe('function');
  });

  it('should instantiate SkillScanner with correct name and label', () => {
    const scanner = new SkillScanner();
    expect(scanner.name).toBe('SkillScanner');
    expect(scanner.label).toBe('🛡️ Skill Scanner');
    expect(typeof scanner.scan).toBe('function');
  });

  it('should instantiate PostureChecker with correct name and label', () => {
    const scanner = new PostureChecker();
    expect(scanner.name).toBe('PostureChecker');
    expect(scanner.label).toBe('📋 Posture Checker');
    expect(typeof scanner.scan).toBe('function');
  });
});
