#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import sys
import httpx
from typing import List

# Setup simple logging
logging.basicConfig(level=logging.ERROR, format='%(message)s')
logger = logging.getLogger("httpx_wrapper")


def classify_httpx_error(exc: Exception) -> str:
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, httpx.InvalidURL):
        return "invalid_url"
    if isinstance(exc, httpx.ConnectError):
        message = str(exc).lower()
        if "name or service not known" in message or "nodename nor servname" in message or "temporary failure in name resolution" in message:
            return "dns_error"
        if "connection refused" in message:
            return "connection_refused"
        if "ssl" in message or "tls" in message or "certificate" in message:
            return "tls_error"
        return "connect_error"
    if isinstance(exc, httpx.HTTPStatusError):
        return "http_error_status"
    return "unexpected_exception"


def build_httpx_error_message(exc: Exception, error_type: str) -> str:
    message = str(exc).strip()
    if message:
        return message

    defaults = {
        "connect_timeout": "connect timeout during request",
        "read_timeout": "read timeout while waiting for response",
        "dns_error": "dns resolution failed for target host",
        "connection_refused": "connection refused by target host",
        "tls_error": "tls handshake or certificate validation failed",
        "connect_error": "connection failed before http response",
        "invalid_url": "input URL is invalid or malformed",
        "http_error_status": "http error status raised by client policy",
        "unexpected_exception": "unexpected exception during probe",
    }
    return defaults.get(error_type, "http probe failed")

async def probe_url(client: httpx.AsyncClient, url: str) -> dict:
    try:
        url = url.strip()
        if not url.startswith("http"):
            url = f"https://{url}" # Default to https
            
        # Try request
        try:
            resp = await client.get(url, follow_redirects=True)
        except httpx.ConnectError:
             # Retry with http
             if url.startswith("https://"):
                 url = url.replace("https://", "http://")
                 resp = await client.get(url, follow_redirects=True)
             else:
                 raise

        return {
            "url": str(resp.url),
            "status_code": resp.status_code,
            "title": "", # TODO: Parse title if needed
            "content_length": len(resp.content),
            "webserver": resp.headers.get("Server", ""),
            "content_type": resp.headers.get("Content-Type", ""),
            "method": "GET",
            "host": resp.url.host,
            "port": resp.url.port or (443 if resp.url.scheme == "https" else 80),
            "scheme": resp.url.scheme,
            "timestamp": "", 
            "failed": False
        }
    except Exception as e:
        error_type = classify_httpx_error(e)
        return {
            "url": url,
            "failed": True,
            "error_type": error_type,
            "error_message": build_httpx_error_message(e, error_type),
        }

async def main():
    parser = argparse.ArgumentParser(description="Wrapper for httpx to emulate ProjectDiscovery httpx")
    parser.add_argument("-l", "--list", help="Input file containing list of URLs")
    parser.add_argument("-json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Output file")
    # Ignored arguments for compatibility
    parser.add_argument("-follow-redirects", action="store_true")
    parser.add_argument("-threads", type=int, default=50)
    parser.add_argument("-silent", action="store_true")
    parser.add_argument("-H", "--header", action="append", help="Custom headers")
    parser.add_argument("-http-proxy", help="HTTP Proxy URL")
    
    # Allow loose parsing for other flags
    args, unknown = parser.parse_known_args()
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, val = h.split(":", 1)
                custom_headers[key.strip()] = val.strip()
    
    targets = []
    
    # Read input
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Input file not found: {args.list}")
            sys.exit(1)
            
    # Also read from stdin if piped? 
    # ProjectDiscovery httpx reads from stdin if no -l. 
    # But pipeline uses -l.
    
    if not targets:
        # Check positional args (urls)
        targets = [arg for arg in unknown if not arg.startswith("-")]

    results = []
    timeout = httpx.Timeout(10.0, connect=5.0)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=args.threads)
    
    client_kwargs = {
        "verify": False,
        "timeout": timeout,
        "limits": limits,
        "headers": custom_headers
    }
    if getattr(args, "http_proxy", None):
        client_kwargs["proxy"] = args.http_proxy
        
    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [probe_url(client, t) for t in targets]
        results = await asyncio.gather(*tasks)
        
    # Output
    output_lines = []
    for res in results:
        if args.json:
            line = json.dumps(res)
            print(line)
            output_lines.append(line)
        else:
            if res.get("failed"):
                print(f"{res['url']} [FAILED:{res.get('error_type', 'unknown')}]")
            else:
                print(f"{res['url']} [{res['status_code']}]")
            
    if args.output:
        try:
            with open(args.output, "w") as f:
                for line in output_lines:
                    f.write(line + "\n")
        except Exception as e:
            logger.error(f"Failed to write output: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
