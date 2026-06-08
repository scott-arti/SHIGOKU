import io
import sys
from typing import Dict, Any
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class Code(BaseTool):
    """Pythonコードをサンドボックス環境で実行"""
    name = "python_code"
    description = "Execute Python code in a restricted sandbox environment"
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Python code to execute"
                        }
                    },
                    "required": ["code"]
                }
            }
        }
    
    def run(self, code: str, allow_imports: bool = False) -> str:
        """
        制限付き環境でPythonコードを実行
        
        Args:
            code: 実行するPythonコード
            allow_imports: 安全なライブラリのインポートを許可するか
            
        Returns:
            実行結果（stdout）
        """
        # stdout/stderrをキャプチャ
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        redirected_output = io.StringIO()
        redirected_error = io.StringIO()
        sys.stdout = redirected_output
        sys.stderr = redirected_error
        
        # 制限付きグローバル環境（危険な関数を制限）
        safe_globals = {
            "__builtins__": {
                "print": print,
                "len": len,
                "range": range,
                "str": str,
                "int": int,
                "float": float,
                "list": list,
                "dict": dict,
                "tuple": tuple,
                "set": set,
                "min": min,
                "max": max,
                "sum": sum,
                "sorted": sorted,
                "enumerate": enumerate,
                "zip": zip,
                "abs": abs,
                "round": round,
                "chr": chr,
                "ord": ord,
                "bin": bin,
                "hex": hex,
                "oct": oct,
                "bool": bool,
                "bytearray": bytearray,
                "bytes": bytes,
                "Exception": Exception,
                "BaseException": BaseException,
                "type": type,
            }
        }
        
        # CTFモードなどで許可される安全なインポート
        if allow_imports:
            # 許可するモジュールリスト
            allowed_modules = {
                "base64", "hashlib", "binascii", "re", "math", "random", 
                "json", "time", "datetime", "struct", "collections", "itertools",
                "functools", "operator", "string", "heapq", "bisect", "copy",
                "Crypto", "Crypto.PublicKey", "Crypto.Cipher", "Crypto.Util",
                "Crypto.Util.number", "Crypto.Hash", "Crypto.Protocol"
            }
            
            # カスタム__import__関数
            def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
                # モジュール名が許可リストにあるか、または許可リストのサブモジュールか確認
                if name in allowed_modules or any(name.startswith(m + ".") for m in allowed_modules):
                    return __import__(name, globals, locals, fromlist, level)
                raise ImportError(f"Import of '{name}' is not allowed in sandbox")

            safe_globals["__builtins__"]["__import__"] = safe_import
            
            # 既存のsafe_globalsにも便利のために追加しておく（importなしで使えるように）
            import base64, hashlib, binascii, re, math, random, json, time, datetime, struct
            
            safe_globals.update({
                "base64": base64,
                "hashlib": hashlib,
                "binascii": binascii,
                "re": re,
                "math": math,
                "random": random,
                "json": json,
                "time": time,
                "datetime": datetime,
                "struct": struct
            })
            
            # Cryptoライブラリがあれば追加
            try:
                from Crypto.PublicKey import RSA
                from Crypto.Cipher import AES, PKCS1_OAEP
                from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, getPrime, isPrime
                
                safe_globals.update({
                    "RSA": RSA,
                    "AES": AES,
                    "PKCS1_OAEP": PKCS1_OAEP,
                    "long_to_bytes": long_to_bytes,
                    "bytes_to_long": bytes_to_long,
                    "inverse": inverse,
                    "getPrime": getPrime,
                    "isPrime": isPrime
                })
            except ImportError:
                pass

        # ParameterFuzzer (Lazy Load)
        # 循環参照や初期化時のエラーを防ぐため、実際にインスタンス化されるまでインポートを遅延させる
        class LazyParameterFuzzer:
            def __new__(cls, *args, **kwargs):
                try:
                    from src.core.attack.param_fuzzer import ParameterFuzzer
                    return ParameterFuzzer(*args, **kwargs)
                except ImportError as e:
                    import traceback
                    print(f"[DEBUG] Failed to import ParameterFuzzer in sandbox (Lazy Load): {e}\n{traceback.format_exc()}", file=sys.stderr)
                    raise e

        safe_globals["ParameterFuzzer"] = LazyParameterFuzzer
        
        try:
            exec(code, safe_globals, {})
            output = redirected_output.getvalue()
            error = redirected_error.getvalue()
            
            result = output
            if error:
                result += f"\n[STDERR]\n{error}"
            
            return result or "Code executed successfully (no output)"
            
        except Exception as e:
            return f"Error executing code: {type(e).__name__}: {str(e)}"
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
