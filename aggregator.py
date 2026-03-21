import requests
import zlib
import math
import mmh3
from bitarray import bitarray

SOURCES = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
]

EXPECTED_ITEMS = 1000000 
FALSE_POSITIVE_RATE = 0.01 

def get_optimal_size(n, p):
    m = -(n * math.log(p)) / (math.log(2)**2)
    return int(m)

def get_optimal_hashes(m, n):
    k = (m / n) * math.log(2)
    return int(k)

def parse_source(text):
    urls = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//')):
            continue
        parts = line.split()
        if len(parts) > 1 and parts[0] in ['0.0.0.0', '127.0.0.1']:
            urls.add(parts[1].lower())
        else:
            urls.add(line.lower())
    return urls

def create_bloom_filter(item_list):
    m = get_optimal_size(EXPECTED_ITEMS, FALSE_POSITIVE_RATE)
    k = get_optimal_hashes(m, EXPECTED_ITEMS)
    bit_cache = bitarray(m)
    bit_cache.setall(0)
    
    print(f"Building filter: {m} bits, {k} hashes for {len(item_list)} items.")
    
    for item in item_list:
        for i in range(k):
            index = mmh3.hash(item, i) % m
            bit_cache[index] = True
            
    return bit_cache.tobytes(), m, k

def run():
    master_list = set()
    print("Fetching feeds...")
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                master_list.update(parse_source(r.text))
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")

    bloom_data, m_size, k_hashes = create_bloom_filter(master_list)
    
    with open("daily_filter.bin", "wb") as f:
        f.write(m_size.to_bytes(4, 'big'))
        f.write(k_hashes.to_bytes(4, 'big'))
        f.write(zlib.compress(bloom_data))
    
    print("Success: daily_filter.bin generated.")

if __name__ == "__main__":
    run()

