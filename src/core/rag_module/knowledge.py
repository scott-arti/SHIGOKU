import os
from typing import List, Dict

class KnowledgeBase:
    """
    Simple Knowledge Base using Markdown files.
    """
    def __init__(self, root_dir: str = "knowledge"):
        self.root_dir = root_dir
        
    def search(self, query: str) -> List[Dict[str, str]]:
        """
        Search for query in markdown files.
        Returns filename and matching context.
        """
        results = []
        query = query.lower()
        
        for root, _, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith(".md"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read()
                            if query in content.lower() or query in file.lower():
                                # Simple extract: First 200 chars or context around match
                                snippet = content[:500] + "..."
                                results.append({
                                    "source": file,
                                    "content": snippet,
                                    "path": path
                                })
                    except Exception as e:
                        print(f"Error reading {path}: {e}")
                        
        return results

# Singleton-ish usage
kb = KnowledgeBase()
