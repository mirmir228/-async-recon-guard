import asyncio
import aiohttp
from datetime import datetime

class SecurityScanner:
    def __init__(self, targets):
        self.targets = targets
        self.results = []
        # Список заголовков, которые ДОЛЖНЫ быть у безопасного сайта
        self.required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

    async def check_headers(self, session, url):
        try:
            async with session.get(url, timeout=10) as resp:
                headers = resp.headers
                missing = [h for h in self.required_headers if h not in headers]
                return {
                    "url": url,
                    "status": resp.status,
                    "missing_headers": missing,
                    "server": headers.get("Server", "Unknown")
                }
        except Exception as e:
            return {"url": url, "error": str(e)}

    async def scan_all(self):
        connector = aiohttp.TCPConnector(limit_per_host=5)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_headers(session, target) for target in self.targets]
            return await asyncio.gather(*tasks)

# Пример запуска (в реальном проекте будет в main.py)
if __name__ == "__main__":
    target_list = ["https://google.com", "https://github.com"]
    scanner = SecurityScanner(target_list)
    
    print(f"[*] Scan started at {datetime.now()}")
    results = asyncio.run(scanner.scan_all())
    
    for res in results:
        if "error" in res:
            print(f"[!] {res['url']}: Error {res['error']}")
        else:
            print(f"[+] {res['url']} (Status: {res['status']})")
            if res['missing_headers']:
                print(f"    [-] Missing: {', '.join(res['missing_headers'])}")
