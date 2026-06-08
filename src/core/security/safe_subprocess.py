import subprocess
import logging
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

class SecurityViolationError(Exception):
    """Raised when a security constraint is violated during command execution."""
    pass

def safe_run(
    command: List[str],
    cwd: Optional[str] = None,
    timeout: Optional[int] = None,
    check: bool = False,
    capture_output: bool = True,
    env: Optional[Dict[str, str]] = None
) -> subprocess.CompletedProcess:
    """
    Secure wrapper for subprocess.run.
    
    Enforces:
    1. shell=False (No shell injection)
    2. List-based arguments (No manual quoting/escaping errors)
    
    Args:
        command: Command and arguments as a list of strings
        cwd: Working directory
        timeout: Timeout in seconds
        check: If True, raise CalledProcessError on non-zero exit code
        capture_output: If True, capture stdout/stderr
        env: Environment variables
        
    Returns:
        subprocess.CompletedProcess object
        
    Raises:
        SecurityViolationError: If security constraints are violated
        subprocess.TimeoutExpired: If timeout is reached
        subprocess.CalledProcessError: If check=True and command fails
    """
    # 1. Input Validation
    if isinstance(command, str):
        raise SecurityViolationError(
            "Security Violation: Command must be a list of strings, not a raw string. "
            "Use shlex.split() if necessary, but prefer explicit list construction."
        )
    
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise SecurityViolationError("Security Violation: Command must be a list of strings.")
        
    if not command:
        raise ValueError("Command list cannot be empty.")

    # 2. Logging (Redact sensitive info if needed in future)
    logger.debug("Executing safe command: %s", command)
    
    try:
        # 3. Secure Execution
        return subprocess.run(
            command,
            cwd=cwd,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=True,
            shell=False,  # CRITICAL: Implicitly enforced
            env=env
        )
    except subprocess.TimeoutExpired as e:
        logger.error("Command timed out after %s seconds: %s", timeout, command)
        raise e
    except Exception as e:
        logger.error("Command execution failed: %s", e)
        raise
