import sys
import json
import base64
import re
from pathlib import Path

def analyze_report(file_path):
    print(f"Analyzing: {file_path}")
    try:
        content = Path(file_path).read_text(encoding='utf-8')
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Find the session-data script tag
    # <script id="session-data" type="application/json">
    # ... base64 data ...
    # </script>
    
    match = re.search(r'<script id="session-data" type="application/json">\s*(.*?)\s*</script>', content, re.DOTALL)
    if not match:
        print("Error: Could not find session-data script tag.")
        return

    raw_data = match.group(1).strip()
    try:
        # Try decoding base64
        decoded_json = base64.b64decode(raw_data).decode('utf-8')
        data = json.loads(decoded_json)
    except Exception as e:
        print(f"Error decoding/parsing JSON: {e}")
        # Fallback: maybe it's raw JSON?
        try:
            data = json.loads(raw_data)
        except:
            print("Failed to parse data as JSON.")
            return

    tasks = data.get("tasks", [])
    print(f"Found {len(tasks)} tasks.")
    
    nuclei_tasks = []
    failed_tasks = []
    success_tasks = []

    for task in tasks:
        task_id = task.get("id")
        name = task.get("name")
        result = task.get("result", {}) or {}
        output = result.get("data", {}).get("output", "") if result.get("data") else ""
        
        # Check for Nuclei usage context
        is_nuclei = "nuclei" in str(task).lower()
        
        status = "✅ Success" if task.get("state") == "success" else "❌ Failed"
        
        print(f"[{status}] Task: {name} (ID: {task_id})")
        
        if output:
            if isinstance(output, (dict, list)):
                output_str = json.dumps(output)
            else:
                output_str = str(output)
                
            # Check for specific errors
            if "Nuclei Error" in output_str:
                print(f"  -> 🚨 NUCLEI ERROR DETECTED")
                print(f"  -> Snippet: {output_str[:200]}...")
            elif "No results found" in output_str:
                print(f"  -> ℹ️  Nuclei ran but found nothing.")
                if is_nuclei:
                    print(f"  -> Snippet: {output_str[:100]}...")
            elif is_nuclei:
                print(f"  -> ✅ Nuclei Output: {output_str[:100]}...")
            else:
                print(f"  -> Output: {output_str[:100]}...")
        else:
            print("  -> No output data.")
            
        print("-" * 30)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_report_json.py <path_to_html>")
        sys.exit(1)
    analyze_report(sys.argv[1])
