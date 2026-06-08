"""PIIMasker のユニットテスト（双方向マスキング対応版）"""
from src.core.security.pii_masker import PIIMasker, PIIPattern, MaskResult, mask_pii, unmask_pii, get_pii_masker


class TestPIIMaskerBasics:
    """基本的なマスキング機能のテスト"""
    
    def test_empty_text(self):
        """空文字列は変更なし"""
        masker = PIIMasker()
        result = masker.mask("")
        assert result.masked == ""
        assert not result.has_pii
    
    def test_no_pii_text(self):
        """PIIを含まないテキストは変更なし"""
        masker = PIIMasker()
        text = "This is a normal text without any sensitive information."
        result = masker.mask(text)
        assert result.masked == text
        assert not result.has_pii
    
    def test_disabled_masker(self):
        """無効化されたマスカーは何もしない"""
        masker = PIIMasker(enabled=False)
        text = "My email is test@example.com"
        result = masker.mask(text)
        assert result.masked == text
        assert not result.has_pii


class TestAPIKeyMasking:
    """APIキーのマスキングテスト"""
    
    def test_openai_api_key(self):
        """OpenAI APIキーのマスク"""
        masker = PIIMasker()
        text = "My API key is sk-1234567890abcdefghijklmnop"
        result = masker.mask(text)
        assert "[PII:OPENAI_API_KEY:" in result.masked
        assert "sk-1234567890abcdefghijklmnop" not in result.masked
        assert result.has_pii
    
    def test_aws_access_key(self):
        """AWS Access Key IDのマスク"""
        masker = PIIMasker()
        text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        result = masker.mask(text)
        assert "[PII:AWS_ACCESS_KEY:" in result.masked
        assert "AKIAIOSFODNN7EXAMPLE" not in result.masked
    
    def test_github_token(self):
        """GitHub Personal Access Tokenのマスク"""
        masker = PIIMasker()
        text = "GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = masker.mask(text)
        assert "[PII:GITHUB_TOKEN:" in result.masked
    
    def test_google_api_key(self):
        """Google APIキーのマスク"""
        masker = PIIMasker()
        text = "Google API: AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
        result = masker.mask(text)
        assert "[PII:GOOGLE_API_KEY:" in result.masked
    
    def test_stripe_key(self):
        """Stripe APIキーのマスク"""
        masker = PIIMasker()
        text = "Stripe: pk_test_1234567890abcdefghijklmn"
        result = masker.mask(text)
        assert "[PII:STRIPE_KEY:" in result.masked


class TestJWTMasking:
    """JWTのマスキングテスト"""
    
    def test_jwt_token(self):
        """JWTのマスク"""
        masker = PIIMasker()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"Token: {jwt}"
        result = masker.mask(text)
        assert "[PII:JWT:" in result.masked
        assert jwt not in result.masked
    
    def test_bearer_token(self):
        """Bearer Tokenのマスク"""
        masker = PIIMasker()
        text = "Authorization: Bearer abc123def456ghi789"
        result = masker.mask(text)
        assert "[PII:BEARER_TOKEN:" in result.masked


class TestPIIMasking:
    """個人情報のマスキングテスト"""
    
    def test_email(self):
        """メールアドレスのマスク"""
        masker = PIIMasker()
        text = "Contact me at john.doe@example.com"
        result = masker.mask(text)
        assert "[PII:EMAIL:" in result.masked
        assert "john.doe@example.com" not in result.masked
    
    def test_phone_jp(self):
        """日本の電話番号のマスク"""
        masker = PIIMasker()
        text = "電話番号: 090-1234-5678"
        result = masker.mask(text)
        assert "[PII:PHONE_JP:" in result.masked
        assert "090-1234-5678" not in result.masked
    
    def test_credit_card(self):
        """クレジットカード番号のマスク"""
        masker = PIIMasker()
        text = "Card: 4111111111111111"
        result = masker.mask(text)
        assert "[PII:CREDIT_CARD:" in result.masked
        assert "4111111111111111" not in result.masked
    
    def test_ipv4(self):
        """IPv4アドレスのマスク"""
        masker = PIIMasker()
        text = "Server IP: 192.168.1.100"
        result = masker.mask(text)
        assert "[PII:IPV4:" in result.masked
        assert "192.168.1.100" not in result.masked
    
    def test_ipv4_whitelist(self):
        """ホワイトリストのIPはマスクしない"""
        masker = PIIMasker()
        text = "Localhost: 127.0.0.1"
        result = masker.mask(text)
        assert "127.0.0.1" in result.masked  # ホワイトリストなのでマスクされない
    
    def test_uuid(self):
        """UUIDのマスク"""
        masker = PIIMasker()
        text = "User ID: 550e8400-e29b-41d4-a716-446655440000"
        result = masker.mask(text)
        assert "[PII:UUID:" in result.masked


class TestPrivateKeyMasking:
    """秘密鍵のマスキングテスト"""
    
    def test_rsa_private_key(self):
        """RSA秘密鍵のマスク"""
        masker = PIIMasker()
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq+fake+key+content+here
-----END RSA PRIVATE KEY-----"""
        result = masker.mask(text)
        assert "[PII:PRIVATE_KEY:" in result.masked
        assert "MIIEowIBAAKCAQEAq" not in result.masked


class TestBidirectionalMasking:
    """双方向マスキング（マスク→復元）のテスト"""
    
    def test_mask_and_unmask(self):
        """マスクして復元"""
        masker = PIIMasker()
        original = "My API key is sk-1234567890abcdefghijklmnop"
        
        # マスク
        result = masker.mask(original)
        assert "sk-1234567890abcdefghijklmnop" not in result.masked
        
        # 復元
        restored = masker.unmask(result.masked)
        assert restored == original
    
    def test_unmask_dict(self):
        """辞書内のトークンを復元"""
        masker = PIIMasker()
        original_key = "sk-1234567890abcdefghijklmnop"
        
        # マスク
        result = masker.mask(f"key: {original_key}")
        token = result.masked.split("key: ")[1]
        
        # 辞書を復元
        tool_args = {"api_key": token, "target": "example.com"}
        restored = masker.unmask_dict(tool_args)
        
        assert restored["api_key"] == original_key
        assert restored["target"] == "example.com"
    
    def test_unmask_nested_dict(self):
        """ネストした辞書内のトークンを復元"""
        masker = PIIMasker()
        original_email = "secret@example.com"
        
        # マスク
        result = masker.mask(original_email)
        token = result.masked
        
        # ネストした辞書を復元
        tool_args = {
            "config": {
                "email": token,
                "enabled": True
            },
            "list": [token, "normal_value"]
        }
        restored = masker.unmask_dict(tool_args)
        
        assert restored["config"]["email"] == original_email
        assert restored["list"][0] == original_email
        assert restored["list"][1] == "normal_value"
    
    def test_same_value_same_token(self):
        """同じ値には同じトークンが割り当てられる（冪等性）"""
        masker = PIIMasker()
        key = "sk-1234567890abcdefghijklmnop"
        
        result1 = masker.mask(f"First: {key}")
        result2 = masker.mask(f"Second: {key}")
        
        # 同じトークンが使われる
        token1 = result1.masked.split("First: ")[1]
        token2 = result2.masked.split("Second: ")[1]
        assert token1 == token2


class TestMaskMessages:
    """メッセージリストのマスキングテスト"""
    
    def test_mask_messages_list(self):
        """メッセージリストのマスク"""
        masker = PIIMasker()
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "My API key is sk-1234567890abcdefghijklmnop"},
        ]
        result = masker.mask_messages(messages)
        
        # 元のリストは変更されない
        assert "sk-1234567890abcdefghijklmnop" in messages[1]["content"]
        
        # マスク済みリストでは置換される
        assert "sk-1234567890abcdefghijklmnop" not in result[1]["content"]
        assert "[PII:OPENAI_API_KEY:" in result[1]["content"]


class TestHelperFunctions:
    """ヘルパー関数のテスト"""
    
    def test_mask_pii_function(self):
        """mask_pii便利関数"""
        # シングルトンをクリア
        get_pii_masker().clear_session()
        
        text = "Email: test@example.com"
        result = mask_pii(text)
        assert "[PII:EMAIL:" in result
        assert "test@example.com" not in result
    
    def test_unmask_pii_function(self):
        """unmask_pii便利関数"""
        masker = get_pii_masker()
        masker.clear_session()
        
        original = "sk-1234567890abcdefghijklmnop"
        masked = mask_pii(f"Key: {original}")
        restored = unmask_pii(masked)
        assert original in restored


class TestSessionManagement:
    """セッション管理のテスト"""
    
    def test_clear_session(self):
        """セッションクリア"""
        masker = PIIMasker()
        masker.mask("sk-1234567890abcdefghijklmnop")
        assert masker.get_token_count() > 0
        
        masker.clear_session()
        assert masker.get_token_count() == 0


class TestCustomPatterns:
    """カスタムパターンのテスト"""
    
    def test_custom_pattern(self):
        """カスタムパターンの追加"""
        custom = [
            PIIPattern(
                name="CUSTOM_ID",
                pattern=r"CUSTOM-[A-Z]{4}-[0-9]{4}",
                description="カスタムID形式",
            )
        ]
        masker = PIIMasker(custom_patterns=custom)
        text = "ID: CUSTOM-ABCD-1234"
        result = masker.mask(text)
        assert "[PII:CUSTOM_ID:" in result.masked
