import logging
import tempfile
import os
from contextlib import contextmanager
from typing import List, Optional, Iterator

from src.core.security.ethics_guard import get_ethics_guard, ActionType, ActionResult

logger = logging.getLogger(__name__)

@contextmanager
def create_batch_file(targets: List[str], prefix: str = "shigoku_batch_") -> Iterator[Optional[str]]:
    """
    ターゲットリストをEthicsGuardで検証し、一時的なターゲットリストファイルを作成する。
    
    Args:
        targets: ターゲット（URL/ドメイン）のリスト
        prefix: 一時ファイル名の接頭辞
        
    Yields:
        str: 一時ファイルへの絶対パス。ターゲットが空またはすべてブロックされた場合はNone。
    """
    guard = get_ethics_guard()
    allowed_targets = []
    
    # 1. Scope Check
    for target in targets:
        result, reason = guard.check_action(ActionType.DNS_LOOKUP, target)
        if result == ActionResult.ALLOWED:
            allowed_targets.append(target)
        else:
            logger.warning("Batch Item Blocked: %s - %s", target, reason)
            
    if not allowed_targets:
        logger.error("No targets allowed after EthicsGuard check. Batch aborted.")
        yield None
        return

    # 2. Create Temporary File
    fd, path = tempfile.mkstemp(suffix=".txt", prefix=prefix, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write("\n".join(allowed_targets) + "\n")
        
        logger.debug("Created batch file with %d targets at %s", len(allowed_targets), path)
        yield path
    finally:
        # 3. Cleanup
        try:
            if os.path.exists(path):
                os.remove(path)
                logger.debug("Removed temporary batch file %s", path)
        except OSError as e:
            logger.error("Failed to remove temporary file %s: %s", path, e)
