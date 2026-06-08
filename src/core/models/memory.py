import json
import os
import time
from datetime import datetime
from typing import List, Dict, Any

class Memory:
    """
    Simple memory management for persisting agent sessions.
    Stores data in an NDJSON file (newline delimited JSON) for efficiency.
    """
    def __init__(self, storage_file: str = "~/.cai_memory.json"):
        self.storage_file = os.path.expanduser(storage_file)
        self._ensure_storage()

    def _ensure_storage(self):
        """Ensure the storage file exists."""
        if not os.path.exists(self.storage_file):
            # Create empty file
            with open(self.storage_file, "a") as f:
                pass

    def search_sessions(self, query: str) -> List[Dict[str, Any]]:
        """
        Search past sessions for keywords.
        Reads line by line (generator would be better but list required).
        """
        matches = []
        query = query.lower()
        
        try:
            with open(self.storage_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        session = json.loads(line)
                        summary = session.get("summary", "").lower()
                        result = session.get("result", "").lower()
                        if query in summary or query in result:
                            matches.append(session)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            return []
                
        return matches

    def save_session(self, session_data: Dict[str, Any]):
        """
        Save a session result.
        Appends to file (O(1)).
        """
        # ID generation is tricky with append-only. 
        # Using timestamp as ID or just random is better, or count lines (slow).
        # We will use timestamp-based ID for simplicity.
        
        new_session = {
            "id": int(time.time() * 1000), # Millisecond timestamp ID
            "timestamp": datetime.now().isoformat(),
            **session_data
        }
        
        with open(self.storage_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(new_session, ensure_ascii=False) + "\n")
        
    def list_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """List most recent sessions."""
        # This requires reading the file. For finding last N, we can read efficiently or just read all.
        # Since this is local CLI, reading all is acceptable for now (< 100MB).
        sessions = []
        try:
            with open(self.storage_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            sessions.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            return []

        # Return simplified view of last N
        result = []
        for s in sessions[-limit:]:
            result.append({
                "id": s.get("id"),
                "action": s.get("summary", "")[:50],
                "agent": s.get("agent"),
                "size": len(str(s)),
                "created": s.get("timestamp")
            })
        return result

    def clear(self):
        """Clear all memory."""
        with open(self.storage_file, "w") as f:
            pass
