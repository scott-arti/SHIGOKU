"""SHIGOKU エントリポイント (python -m src 用)

Phase 4: レガシー削除により、シンプルなリダイレクトに変更。
全機能は src.main:main に統合済み。
"""
from src.main import main

if __name__ == "__main__":
    main()
