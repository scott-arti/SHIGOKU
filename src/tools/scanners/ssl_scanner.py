import logging
import ssl
import socket
import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SSLScanner:
    """Native SSL/TLS Configuration Scanner"""
    
    async def scan(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Wrapper to run synchronous scan in thread"""
        import asyncio
        return await asyncio.to_thread(self._scan_sync, host, port)

    def _scan_sync(self, host: str, port: int) -> Dict[str, Any]:
        """Check SSL certificate and basic config (Synchronous)"""
        result = {
            "is_valid": False,
            "issues": []
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False # We want to inspect even if invalid
            context.verify_mode = ssl.CERT_NONE # Manual verification
            
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
            conn.settimeout(5.0)
            
            try:
                conn.connect((host, port))
                _ = conn.getpeercert(binary_form=True)
                # Parse cert (basic)
                # Standard library doesn't parse binary cert easily without loading it back or using OpenSSL
                # But if we use CERT_OPTIONAL/REQUIRED it returns dict
                
                # Re-connect for dict cert
                conn.close()
                context.verify_mode = ssl.CERT_OPTIONAL
                conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
                conn.connect((host, port))
                cert_dict = conn.getpeercert()
                
                if not cert_dict:
                    result["issues"].append("No certificate returned")
                    return result
                
                # Check Expiry
                not_after_str = cert_dict.get('notAfter')
                if not_after_str:
                    # 'May  9 12:00:00 2026 GMT'
                    try:
                        expire_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire_date - datetime.datetime.now()).days
                        result["days_left"] = days_left
                        if days_left < 30:
                            result["issues"].append(f"Certificate expires soon ({days_left} days)")
                        if days_left < 0:
                            result["issues"].append("Certificate expired")
                    except:
                        pass
                
                # Cipher check
                cipher = conn.cipher()
                if cipher:
                    result["cipher"] = cipher
                    # Basic weak cipher check
                    if "RC4" in cipher[0] or "MD5" in cipher[0]:
                        result["issues"].append(f"Weak Cipher detected: {cipher[0]}")

                result["subject"] = dict(x[0] for x in cert_dict.get('subject', []))
                result["issuer"] = dict(x[0] for x in cert_dict.get('issuer', []))
                
                if not result["issues"]:
                    result["is_valid"] = True
                    
            finally:
                conn.close()
                
        except ssl.SSLError as e:
            result["issues"].append(f"SSL Error: {e}")
        except socket.error as e:
            result["issues"].append(f"Connection Error: {e}")
        except Exception as e:
            result["issues"].append(f"Error: {e}")
            
        return result
