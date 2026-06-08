import os
import shlex
from pathlib import Path

# Mock settings
class Settings:
    tool_nuclei_path = "nuclei"
    home = str(Path.home())

settings = Settings()

def resolve_template_arg(arg: str) -> str:
    """
    Simulates the logic we want to implement:
    If arg indicates a template that doesn't exist, try to find it in nuclei-templates.
    """
    if not (arg.endswith('.yaml') or arg.endswith('.yml')):
        return arg
        
    # Check if it exists as is
    if os.path.exists(arg):
        return arg
        
    # Check if it's a relative path that fails
    filename = Path(arg).name
    
    # Simulate finding it in nuclei-templates
    nuclei_dir = Path(settings.home) / "nuclei-templates"
    if not nuclei_dir.exists():
        print(f"Warning: {nuclei_dir} does not exist")
        return arg
        
    # Search (this is slow, but we'll optimize in prod key-value map)
    # For test, just check if we can find 'cors-misconfig.yaml'
    found = list(nuclei_dir.rglob(filename))
    if found:
        print(f"Resolving {arg} -> {found[0]}")
        return str(found[0])
    
    return arg

def parse_and_fix_cmd(extra_args: str):
    args = shlex.split(extra_args)
    new_args = []
    skip_next = False
    
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
            
        if arg in ["-t", "-templates"]:
            if i + 1 < len(args):
                tpl_path = args[i+1]
                resolved = resolve_template_arg(tpl_path)
                new_args.extend([arg, resolved])
                skip_next = True
            else:
                new_args.append(arg)
        else:
            new_args.append(arg)
            
    return new_args

# Test Cases
test_args = [
    "-t vulnerabilities/generic/cors-misconfig.yaml",
    "-t cves/2023/CVE-2023-1234.yaml",
    "-t http/cves/2023/CVE-2023-1234.yaml" # Valid one if exists
]

print("--- Testing Path Resolution ---")
for t in test_args:
    print(f"Original: {t}")
    fixed = parse_and_fix_cmd(t)
    print(f"Fixed:    {fixed}")
    print("-" * 20)
