"""DEV_MODE provider for recon command outputs and fixture artifacts."""

from __future__ import annotations

from pathlib import Path


class ReconDemoProvider:
    """Provide deterministic command outputs and fixture files for DEV_MODE."""

    def check_tools(self, tools: list[str]) -> None:
        """DEV_MODE treats required tools as available."""
        return None

    def is_tool_available(self, tool_name: str) -> bool:
        """DEV_MODE advertises tools as available."""
        return True

    def get_command_output(self, cmd: list[str], mock_output: str = "") -> str:
        """Return explicit mock output or a built-in fixture for the tool."""
        if mock_output:
            return mock_output

        tool = cmd[0] if cmd else ""
        domain = self._extract_domain(cmd)

        if tool in {"subfinder", "amass", "assetfinder"}:
            return f"www.{domain}\napi.{domain}\ndev.{domain}\n"

        if tool == "httpx":
            import json

            return json.dumps(
                {
                    "url": f"https://www.{domain}",
                    "status_code": 200,
                    "title": "Example Domain",
                    "webserver": "nginx",
                    "tech": ["React", "Cloudflare"],
                }
            ) + "\n"

        if tool == "katana":
            return f"https://www.{domain}/api/v1\nhttps://www.{domain}/login\n"

        if tool == "whatweb":
            return (
                f'[ {{"target":"https://www.{domain}","plugins":'
                f'{{"HTTPServer":{{"string":["nginx"]}}}}}}]'
            )

        return ""

    def write_resolvers_file(self, output_path: Path, count: int) -> Path:
        """Write deterministic resolver fixtures for DEV_MODE."""
        resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"][: max(1, count)]
        output_path.write_text("\n".join(resolvers))
        return output_path

    def ensure_whatweb_file(self, output_path: Path, output: str) -> Path:
        """Persist whatweb fixture output when the tool did not create a file."""
        if not output_path.exists():
            output_path.write_text(output)
        return output_path

    def _extract_domain(self, cmd: list[str]) -> str:
        """Extract domain-like input from a tool command."""
        domain = "example.com"
        for i, part in enumerate(cmd):
            if part in {"-d", "--domain", "-u", "--url"} and i + 1 < len(cmd):
                domain = cmd[i + 1].lstrip("*.")
                break
        return domain
