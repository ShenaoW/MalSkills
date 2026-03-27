#!/usr/bin/env python3
"""语义搜索新闻（market.ft.tech）"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
SAFE_URLOPENER = urllib.request.build_opener()

BASE_URL = "https://market.ft.tech"

def safe_urlopen(req_or_url):
    if isinstance(req_or_url, urllib.request.Request):
        url = req_or_url.full_url
    else:
        url = str(req_or_url)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "market.ft.tech":
        print(f"Invalid URL for safe_urlopen: {url}", file=sys.stderr)
        sys.exit(1)
    return SAFE_URLOPENER.open(req_or_url)



def main():
    parser = argparse.ArgumentParser(description="语义搜索新闻")
    parser.add_argument(
        "--query",
        required=True,
        help="搜索文字，如：人工智能",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="返回条数，默认 10",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="年份，仅支持当年，用于限定搜索范围；不传则由服务端决定",
    )
    args = parser.parse_args()

    params = {"query": args.query, "limit": args.limit}
    if args.year is not None:
        params["year"] = args.year

    url = BASE_URL + "/data/api/v1/market/data/semantic-search-news?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method="GET")

    try:
        with safe_urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        print(json.dumps(data, ensure_ascii=False, indent=2))
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
