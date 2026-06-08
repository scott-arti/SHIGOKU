"""
Legal Disclaimer - 法的免責事項表示

起動時警告と同意確認
"""

import logging
import sys
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# 免責事項テキスト
DISCLAIMER_TEXT = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         ⚠️  SHIGOKU 法的免責事項  ⚠️                          ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  このツールは、正規の許可を得たセキュリティテストおよびバグバウンティ        ║
║  プログラムでの使用のみを目的としています。                                  ║
║                                                                              ║
║  ▶ 使用条件:                                                                 ║
║    • ターゲットの所有者から書面による明示的な許可を取得していること          ║
║    • バグバウンティプログラムのスコープ内でのみ使用すること                  ║
║    • 全ての適用法規を遵守すること                                            ║
║                                                                              ║
║  ▶ 禁止事項:                                                                 ║
║    • 許可なくシステムにアクセスすること                                      ║
║    • サービス妨害（DoS）攻撃を行うこと                                       ║
║    • データの破壊、改ざん、窃取を行うこと                                    ║
║    • 第三者のプライバシーを侵害すること                                      ║
║                                                                              ║
║  ▶ 免責:                                                                     ║
║    開発者は、本ツールの不正使用または誤用によって生じた                      ║
║    いかなる損害についても責任を負いません。                                  ║
║    ユーザーは、自己の責任において本ツールを使用するものとします。            ║
║                                                                              ║
║  ▶ 監査ログ:                                                                 ║
║    全ての操作は監査ログに記録されます。                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

DISCLAIMER_SHORT = """
⚠️  SHIGOKU - 許可されたテストのみに使用してください
   不正使用は法律で禁止されています。
"""

CONSENT_PROMPT = """
上記の免責事項を理解し、正規の許可を得た上で使用することに同意しますか？

[Y]es / [N]o: """


class LegalDisclaimer:
    """
    法的免責事項表示
    
    機能:
    - 起動時警告表示
    - 同意確認
    - 同意ログ記録
    """
    
    def __init__(
        self,
        require_consent: bool = True,
        log_consent: bool = True
    ):
        self.require_consent = require_consent
        self.log_consent = log_consent
        self._consented = False
        self._consent_time: Optional[datetime] = None
    
    def show(self, short: bool = False):
        """
        免責事項を表示
        
        Args:
            short: 短縮版を表示
        """
        if short:
            print(DISCLAIMER_SHORT)
        else:
            print(DISCLAIMER_TEXT)
    
    def require_consent(self) -> bool:
        """
        同意を要求
        
        Returns:
            同意した場合True
        """
        self.show()
        
        try:
            response = input(CONSENT_PROMPT).strip().lower()
            
            if response in ["y", "yes"]:
                self._consented = True
                self._consent_time = datetime.utcnow()
                
                if self.log_consent:
                    self._log_consent()
                
                print("\n✓ 同意が記録されました。使用条件を遵守してください。\n")
                return True
            else:
                print("\n✗ 同意が得られませんでした。プログラムを終了します。\n")
                return False
                
        except (KeyboardInterrupt, EOFError):
            print("\n\n✗ 中断されました。\n")
            return False
    
    def check_or_exit(self):
        """同意確認、なければ終了"""
        if not self.require_consent():
            sys.exit(1)
    
    def _log_consent(self):
        """同意をログに記録"""
        import os
        from pathlib import Path
        
        log_dir = Path(os.path.expanduser("~/.shigoku/legal"))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / "consent.log"
        
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{self._consent_time.isoformat()}Z - Consent given\n")
        
        logger.info("Legal consent logged at %s", self._consent_time)
    
    @property
    def consented(self) -> bool:
        """同意済みか"""
        return self._consented
    
    def get_banner(self) -> str:
        """短いバナーを取得"""
        return DISCLAIMER_SHORT


def show_disclaimer(require_consent: bool = True) -> bool:
    """
    免責事項表示と同意確認
    
    Args:
        require_consent: 同意を要求するか
    
    Returns:
        同意した場合True
    """
    disclaimer = LegalDisclaimer(require_consent=require_consent)
    
    if require_consent:
        return disclaimer.require_consent()
    else:
        disclaimer.show(short=True)
        return True


def get_disclaimer_text(short: bool = False) -> str:
    """免責事項テキスト取得"""
    return DISCLAIMER_SHORT if short else DISCLAIMER_TEXT
