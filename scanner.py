import asyncio
import aiohttp
import argparse
import logging
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

class SecurityScanner:
    def __init__(self, targets, timeout=10):
        self.targets = targets
        self.timeout = timeout
        self.required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

    async def check_url(self, session, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            async with session.get(url, timeout=self.timeout) as resp:
                headers = resp.headers
                missing = [h for h in self.required_headers if h not in headers]
                
                logger.info(f"Scanned {url} - Status: {resp.status}")
                return {
                    "url": url,
                    "status": resp.status,
                    "missing_headers": missing,
                    "server": headers.get("Server", "Unknown")
                }
        except asyncio.TimeoutError:
            logger.error(f"Timeout while scanning {url}")
        except Exception as e:
            logger.error(f"Failed to scan {url}: {str(e)}")
        return None

    async def run(self):
        connector = aiohttp.TCPConnector(limit_per_host=5)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_url(session, target) for target in self.targets]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r]

def main():
    parser = argparse.ArgumentParser(description="AsyncReconGuard: Fast Security Header Auditor")
    parser.add_argument("-u", "--urls", nargs="+", help="List of URLs to scan", required=True)
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    
    args = parser.parse_args()

    scanner = SecurityScanner(args.urls, timeout=args.timeout)
    
    print("\n" + "="*50)
    print(f" AsyncReconGuard Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("="*50 + "\n")

    results = asyncio.run(scanner.run())

    for res in results:
        status_icon = "✅" if not res['missing_headers'] else "⚠️"
        print(f"{status_icon} URL: {res['url']}")
        if res['missing_headers']:
            print(f"   [-] Missing Headers: {', '.join(res['missing_headers'])}")
        print("-" * 30)

if __name__ == "__main__":
    main()
