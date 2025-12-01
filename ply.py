import asyncio
import random
import time
import os
import sys
from datetime import datetime
from playwright.async_api import async_playwright
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('bunny_stress.log')
    ]
)
logger = logging.getLogger(__name__)

# Configuration from environment
TARGET_URL = os.getenv("TARGET_URL", "https://example.com/")
DURATION = int(os.getenv("DURATION", "30"))   # seconds
CONCURRENCY = int(os.getenv("CONCURRENCY", "20"))  # number of concurrent tabs
REQ_PER_BATCH = int(os.getenv("REQ_PER_BATCH", "3"))  # parallel requests per batch
MAX_RPS_PER_TAB = float(os.getenv("MAX_RPS_PER_TAB", "2.0"))  # max RPS per tab
USE_PAGE_LOAD = os.getenv("USE_PAGE_LOAD", "false").lower() == "true"  # use full page load instead of API

# Enhanced fingerprinting
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

ACCEPT_LANG = [
    "en-US,en;q=0.9",
    "vi-VN,vi;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080, "device_scale_factor": 1},
    {"width": 1366, "height": 768, "device_scale_factor": 1},
    {"width": 1536, "height": 864, "device_scale_factor": 1},
    {"width": 1440, "height": 900, "device_scale_factor": 1},
    {"width": 1280, "height": 720, "device_scale_factor": 1},
    {"width": 375, "height": 667, "device_scale_factor": 2},  # Mobile
    {"width": 414, "height": 896, "device_scale_factor": 3},  # Mobile
]

TIMEZONES = [
    "America/New_York",
    "Europe/London",
    "Europe/Paris",
    "Asia/Tokyo",
    "Asia/Ho_Chi_Minh",
    "Australia/Sydney",
    "America/Los_Angeles",
    "Europe/Berlin",
    "Asia/Singapore",
    "America/Chicago",
]

# Global statistics
class Stats:
    def __init__(self):
        self.success = 0
        self.failed = 0
        self.blocked = 0
        self.timeout = 0
        self.start_time = None
        self.status_codes = {}
        self.total_bytes = 0
    
    def increment(self, status_code, bytes_received=0):
        if 200 <= status_code < 300:
            self.success += 1
        elif status_code in [403, 429, 503]:
            self.blocked += 1
        elif status_code == -1:  # Timeout
            self.timeout += 1
        else:
            self.failed += 1
        
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
        self.total_bytes += bytes_received
    
    def get_total(self):
        return self.success + self.failed + self.blocked + self.timeout
    
    def get_rps(self):
        if not self.start_time:
            return 0
        elapsed = time.time() - self.start_time
        return self.get_total() / elapsed if elapsed > 0 else 0

stats = Stats()

def add_random_params(url):
    """Add random query parameters to bypass cache"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    # Add random parameters
    random_params = {
        'v': str(random.randint(1000, 9999)),
        't': str(int(time.time() * 1000)),
        'r': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
        'cb': str(random.randint(1, 1000000))
    }
    
    query.update(random_params)
    
    # Rebuild URL
    new_query = urlencode(query, doseq=True)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

def get_random_headers(ua, lang):
    """Generate random browser-like headers"""
    referers = [
        'https://www.google.com/',
        'https://www.facebook.com/',
        'https://twitter.com/',
        'https://www.youtube.com/',
        'https://www.reddit.com/',
        'https://www.linkedin.com/',
        'https://github.com/',
        'https://stackoverflow.com/',
        'https://medium.com/',
        'https://news.ycombinator.com/',
    ]
    
    return {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': lang,
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': random.choice(referers),
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
        'Sec-Fetch-User': '?1',
        'Cache-Control': random.choice(['max-age=0', 'no-cache', '']),
        'User-Agent': ua,
    }

async def setup_stealth_context(browser, worker_id):
    """Setup stealth browser context with randomized fingerprint"""
    ua = random.choice(USER_AGENTS)
    lang = random.choice(ACCEPT_LANG)
    viewport = random.choice(VIEWPORTS)
    timezone = random.choice(TIMEZONES)
    
    context = await browser.new_context(
        viewport=viewport,
        user_agent=ua,
        locale=lang.split(',')[0].split('-')[0],
        timezone_id=timezone,
        permissions=[],
        geolocation=None,
        has_touch=viewport['width'] < 768,  # Mobile if small
        is_mobile=viewport['width'] < 768,
        device_scale_factor=viewport.get('device_scale_factor', 1),
        color_scheme=random.choice(['light', 'dark']),
        reduced_motion='reduce',
        forced_colors='none',
        accept_downloads=False,
        extra_http_headers=get_random_headers(ua, lang)
    )
    
    # Stealth injection to hide automation
    await context.add_init_script("""
        // Override navigator properties
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
        
        // Override languages
        Object.defineProperty(navigator, 'languages', {
            get: () => [navigator.language || 'en-US', 'en']
        });
        
        // Override permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        
        // Override plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });
        
        // Override hardwareConcurrency
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => 8
        });
        
        // Chrome only
        if (window.chrome) {
            window.chrome = {
                ...window.chrome,
                runtime: {},
                loadTimes: () => {},
                csi: () => {},
                app: {},
            };
        }
        
        // Spoof screen properties
        Object.defineProperty(screen, 'availWidth', {
            get: () => window.innerWidth
        });
        Object.defineProperty(screen, 'availHeight', {
            get: () => window.innerHeight
        });
        
        // Randomize canvas fingerprint
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
            const context = this.getContext('2d');
            if (context) {
                // Add slight noise
                const imageData = context.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < imageData.data.length; i += 10) {
                    imageData.data[i] += Math.floor(Math.random() * 3) - 1;
                }
                context.putImageData(imageData, 0, 0);
            }
            return originalToDataURL.apply(this, args);
        };
    """)
    
    return context

async def make_request_api(context, url, request_id):
    """Make request using context API (faster)"""
    try:
        # Add random delay between requests
        await asyncio.sleep(random.uniform(0.05, 0.3))
        
        # Add random parameters
        target_url = add_random_params(url)
        
        # Make request with timeout
        response = await context.request.get(
            target_url,
            timeout=15000,
            fail_on_status_code=False
        )
        
        # Read response body (partial)
        try:
            body = await response.body()
            content_length = len(body)
        except:
            content_length = 0
        
        stats.increment(response.status, content_length)
        
        # Random delay after response
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        return response.status
        
    except asyncio.TimeoutError:
        stats.increment(-1)
        logger.debug(f"Request {request_id}: Timeout")
        return -1
    except Exception as e:
        logger.debug(f"Request {request_id}: Error - {str(e)}")
        stats.increment(0)
        return 0

async def make_request_page(context, url, request_id):
    """Make request using full page load (more realistic but slower)"""
    try:
        page = await context.new_page()
        
        # Add random parameters
        target_url = add_random_params(url)
        
        # Navigate with realistic wait
        response = await page.goto(
            target_url,
            wait_until=random.choice(['domcontentloaded', 'load', 'networkidle']),
            timeout=20000
        )
        
        # Simulate human behavior
        if random.random() > 0.3:
            # Random scroll
            await page.mouse.wheel(0, random.randint(100, 500))
            await asyncio.sleep(random.uniform(0.2, 1.0))
        
        if random.random() > 0.7:
            # Random click
            await page.mouse.click(
                random.randint(100, 500),
                random.randint(100, 300),
                delay=random.randint(100, 300)
            )
            await asyncio.sleep(random.uniform(0.5, 2.0))
        
        status = response.status if response else 0
        stats.increment(status)
        
        await asyncio.sleep(random.uniform(1.0, 3.0))
        await page.close()
        
        return status
        
    except Exception as e:
        logger.debug(f"Request {request_id}: Error - {str(e)}")
        stats.increment(0)
        return 0

async def worker(playwright, worker_id, stop_event):
    """Worker that runs in each tab"""
    # Random browser fingerprint for each worker
    browser_args = [
        '--disable-blink-features=AutomationControlled',
        '--disable-dev-shm-usage',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-site-isolation-trials',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-ipc-flooding-protection',
        '--disable-hang-monitor',
        '--disable-sync',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-component-extensions-with-background-pages',
        '--disable-component-update',
        '--disable-domain-reliability',
        '--disable-breakpad',
        '--disable-crash-reporter',
        '--no-zygote',
        '--no-service-autorun',
        '--user-agent=' + random.choice(USER_AGENTS),
        '--window-size=' + str(random.choice([1920, 1366, 1536])) + ',' + str(random.choice([1080, 768, 864])),
    ]
    
    browser = await playwright.chromium.launch(
        headless=True,
        args=browser_args
    )
    
    context = await setup_stealth_context(browser, worker_id)
    
    request_count = 0
    start_time = time.time()
    
    try:
        while not stop_event.is_set() and (time.time() - start_time) < DURATION:
            # Calculate interval for RPS control
            interval = 1.0 / MAX_RPS_PER_TAB if MAX_RPS_PER_TAB > 0 else 0
            
            # Prepare batch of requests
            batch_start = time.time()
            tasks = []
            
            for i in range(REQ_PER_BATCH):
                request_id = f"W{worker_id}-R{request_count + i}"
                if USE_PAGE_LOAD:
                    task = make_request_page(context, TARGET_URL, request_id)
                else:
                    task = make_request_api(context, TARGET_URL, request_id)
                tasks.append(task)
            
            # Execute batch in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            request_count += REQ_PER_BATCH
            
            # Control RPS - ensure we don't exceed max RPS
            batch_time = time.time() - batch_start
            min_batch_time = REQ_PER_BATCH * interval if interval > 0 else 0
            
            if min_batch_time > batch_time:
                await asyncio.sleep(min_batch_time - batch_time)
                
    except Exception as e:
        logger.error(f"Worker {worker_id} error: {str(e)}")
    finally:
        await context.close()
        await browser.close()
        logger.info(f"Worker {worker_id} completed {request_count} requests")

async def monitor_stats(stop_event):
    """Monitor and display statistics"""
    last_total = 0
    last_time = time.time()
    
    while not stop_event.is_set():
        await asyncio.sleep(5)
        
        current_total = stats.get_total()
        current_time = time.time()
        
        if stats.start_time:
            elapsed = current_time - stats.start_time
            rps = (current_total - last_total) / (current_time - last_time) if current_time > last_time else 0
            
            print(f"\n[Monitor] Elapsed: {elapsed:.1f}s | Total: {current_total} | "
                  f"Success: {stats.success} | Failed: {stats.failed} | "
                  f"Blocked: {stats.blocked} | Current RPS: {rps:.2f}")
            
            if elapsed > 10:  # Print detailed stats after warm-up
                print(f"  Status Codes: {dict(sorted(stats.status_codes.items()))}")
                print(f"  Avg RPS: {stats.get_rps():.2f} | Data: {stats.total_bytes / 1024:.1f} KB")
        
        last_total = current_total
        last_time = current_time

async def main():
    print(f"\n{'='*60}")
    print("BUNNY.NET STRESS TEST TOOL - ENHANCED VERSION")
    print(f"{'='*60}")
    print(f"Target URL: {TARGET_URL}")
    print(f"Duration: {DURATION}s | Concurrency: {CONCURRENCY} tabs")
    print(f"Requests per batch: {REQ_PER_BATCH} | Max RPS per tab: {MAX_RPS_PER_TAB}")
    print(f"Mode: {'Full Page Load' if USE_PAGE_LOAD else 'API Request'}")
    print(f"{'='*60}\n")
    
    stats.start_time = time.time()
    stop_event = asyncio.Event()
    
    # Start monitor
    monitor_task = asyncio.create_task(monitor_stats(stop_event))
    
    # Start workers
    async with async_playwright() as p:
        tasks = []
        for i in range(CONCURRENCY):
            task = asyncio.create_task(worker(p, i, stop_event))
            tasks.append(task)
            # Stagger worker startup
            await asyncio.sleep(random.uniform(0.1, 0.5))
        
        # Wait for duration
        await asyncio.sleep(DURATION)
        stop_event.set()
        
        # Wait for workers to complete
        await asyncio.gather(*tasks, return_exceptions=True)
    
    # Stop monitor
    await monitor_task
    
    # Final statistics
    print(f"\n{'='*60}")
    print("FINAL RESULTS")
    print(f"{'='*60}")
    total_time = time.time() - stats.start_time
    total_requests = stats.get_total()
    
    print(f"Total Requests: {total_requests}")
    print(f"Successful (2xx): {stats.success}")
    print(f"Failed: {stats.failed}")
    print(f"Blocked (403/429/503): {stats.blocked}")
    print(f"Timeouts: {stats.timeout}")
    print(f"Total Duration: {total_time:.2f}s")
    print(f"Average RPS: {total_requests / total_time:.2f}")
    print(f"Data Transferred: {stats.total_bytes / 1024:.1f} KB")
    print(f"Status Code Distribution: {dict(sorted(stats.status_codes.items()))}")
    
    success_rate = (stats.success / total_requests * 100) if total_requests > 0 else 0
    print(f"Success Rate: {success_rate:.1f}%")
    print(f"{'='*60}")

def run():
    """Main entry point with error handling"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    run()
