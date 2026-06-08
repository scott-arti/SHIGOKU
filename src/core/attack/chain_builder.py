from dataclasses import dataclass, field
from typing import List, Optional
from src.core.models.finding import Finding, VulnType, Severity

@dataclass
class ExploitChain:
    """
    複数の Finding を組み合わせた攻撃チェーン（脆弱性連鎖）のモデル
    """
    name: str
    description: str
    severity: str
    component_findings: List[Finding] = field(default_factory=list)
    required_conditions: List[str] = field(default_factory=list)
    proof_of_concept: Optional[str] = None
    
    def to_finding(self) -> Finding:
        """
        ExploitChain 自体を昇格した 1 つの Finding として返す
        """
        details = (
            f"This is a chained exploit combining {len(self.component_findings)} findings:\n"
            + "\n".join([f"- {f.title} ({f.severity.name})" for f in self.component_findings])
            + f"\n\nAttack Condition: {', '.join(self.required_conditions)}"
            + (f"\nPoC:\n{self.proof_of_concept}" if self.proof_of_concept else "")
        )
        return Finding(
            vuln_type=self.component_findings[0].vuln_type if self.component_findings else VulnType.DEBUG_ENABLED,
            severity=Severity[self.severity.upper()],
            title=f"Attack Chain: {self.name}",
            description=self.description,
            target_url=self.component_findings[0].target_url if self.component_findings else "Multiple",
            additional_info={"chain_details": details}
        )


class ChainBuilder:
    """
    個別に見つかった Finding を解析し、より深刻な Attack Chain を推論（または構築）するクラス
    """
    def __init__(self):
        # 既知の Attack Chain シナリオルール
        self.chain_scenarios = [
            {
                "name": "Account Takeover via XSS and Missing CSRF",
                "severity": "CRITICAL",
                "required_types": ["xss", "csrf"],
                "description": "Cross-Site Scripting (XSS) is combined with a missing CSRF token to perform sensitive actions on behalf of the user."
            },
            {
                "name": "Data Exfiltration via IDOR and Open Redirect",
                "severity": "HIGH",
                "required_types": ["idor", "redirect"],
                "description": "An Open Redirect is used to bypass CORS or referer checks to exploit an IDOR vulnerability, exposing sensitive user data."
            },
            {
                "name": "Privilege Escalation via Mass Assignment and CSRF",
                "severity": "CRITICAL",
                "required_types": ["mass assignment", "csrf"],
                "description": "Missing CSRF token allows an attacker to automatically trigger a Mass Assignment vulnerability resulting in Privilege Escalation."
            }
        ]

    def analyze(self, findings: List[Finding]) -> List[ExploitChain]:
        """
        提供された Finding のリストから、成立しうる Attack Chain を推論する
        
        Args:
            findings: 現在までに発見された脆弱性 (Finding オブジェクトのリスト)
            
        Returns:
            List[ExploitChain]: 構築された攻撃チェーンのリスト
        """
        chains = []
        
        # タイトルや説明に含まれるキーワードベースで型を分類する簡易ロジック
        def has_keyword(finding: Finding, keyword: str) -> bool:
            return keyword.lower() in finding.title.lower() or keyword.lower() in finding.description.lower()

        for scenario in self.chain_scenarios:
            matched_findings = []
            for req in scenario["required_types"]:
                # この requirement に合致する finding を探す
                matches = [f for f in findings if has_keyword(f, req)]
                if matches:
                    matched_findings.append(matches[0]) # とりあえず最初の1件をマッチさせる
            
            # 必要なすべてが揃っていれば Chain 成立
            if len(matched_findings) == len(scenario["required_types"]):
                chain = ExploitChain(
                    name=scenario["name"],
                    description=scenario["description"],
                    severity=scenario["severity"],
                    component_findings=matched_findings,
                    required_conditions=scenario["required_types"]
                )
                chains.append(chain)
                
        return chains

    def build_custom_chain(self, name: str, description: str, severity: str, findings: List[Finding], poc: str = "") -> ExploitChain:
        """
        LLMエージェントなどが任意に構成したチェーンを登録する
        """
        return ExploitChain(
            name=name,
            description=description,
            severity=severity,
            component_findings=findings,
            proof_of_concept=poc
        )
