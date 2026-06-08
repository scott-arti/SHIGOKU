from typing import Dict, Any
from src.core.rag_module.knowledge import kb

class KnowledgeTool:
    """
    Tool to search the internal knowledge base.
    """
    name = "search_knowledge"
    description = "Search the internal knowledge base (cheatsheets, docs) for tools, commands, or techniques. Use keyword queries."

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Keywords to search for (e.g. 'nmap', 'privesc linux')."
                        }
                    },
                    "required": ["query"]
                }
            }
        }

    def run(self, query: str) -> str:
        results = kb.search(query)
        if not results:
            return f"No knowledge found for '{query}'."
        
        output = [f"Found {len(results)} matches for '{query}':"]
        for res in results[:3]: # Limit to top 3
            output.append(f"\n--- Source: {res['source']} ---\n{res['content']}\n")
        
        return "\n".join(output)
