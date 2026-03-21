import requests
import zlib

SOURCES = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
]

def build_daily_filter():
    master_list = set()
    for url in SOURCES:
        try:
            response = requests.get(url, timeout=10)
            master_list.update(parse_source(response.text))
        except:
            continue
    
    bloom_binary = create_bloom_filter(master_list)
    
    with open("daily_filter.bin", "wb") as f:
        f.write(zlib.compress(bloom_binary))
