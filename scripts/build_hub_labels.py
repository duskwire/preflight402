"""Build the vendored hub-address exclusion set from eth-labels (MIT).

Downloads the curated Etherscan-family label dataset from
github.com/dawsbot/eth-labels (branch v1, MIT license) and filters it down to
labels that mark FUNDING HUBS: entities whose wallets first-fund many
unrelated users (CEX hot wallets, instant swappers, fiat on-ramps, bridges,
mixers, ERC-4337 bundlers/paymasters, relayers, mining pools). Using one of
these as a first-funder edge would collapse unrelated reviewers into one
false Sybil cluster (Research4-M6-sybil.md §3), so the Sybil filter refuses
to cluster through them.

Addresses from ALL chains in the dataset are kept: hub wallets are EOAs, and
the same key controls the same address on every EVM chain, so an Ethereum
Coinbase hot wallet is the same hub on Base.

Deliberately NOT included: DEX/DeFi protocol labels (their addresses are
contracts — the eth_getCode EOA rule already excludes them), and
scam/exploit/sanctions labels (a different signal than "funding hub").

Usage:
    uv run python scripts/build_hub_labels.py [--csv accounts.csv]

Writes src/preflight402/reputation/data/hub_addresses.txt.gz (one lowercased
address per line, sorted, deduped; '#' lines are comments). Commit the result.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import sys
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/dawsbot/eth-labels/v1/data/csv/accounts.csv"
OUT_PATH = Path(__file__).parent.parent / "src/preflight402/reputation/data/hub_addresses.txt.gz"

# Label slugs (the dataset's `label` column) that mark funding hubs.
HUB_LABELS = frozenset(
    {
        # generic categories
        "exchange",
        "bridge",
        "fiat-gateway",
        "hot-wallet",
        "cold-wallet",
        "otc",
        "payments",
        "mixer",
        "ethereum-mixer",
        # mixers (named)
        "tornado-cash",
        "typhoon-cash",
        "typhoon-network",
        # centralized exchanges, custodial platforms, instant swappers, ramps
        "abcc",
        "abra",
        "alphapo",
        "altcoin-trader",
        "ascendex",
        "azbit",
        "bgogo",
        "bigone",
        "bilaxy",
        "binance",
        "binance-charity",
        "bitbank",
        "bitbuy",
        "bitfinex",
        "bitflyer",
        "bitget",
        "bithumb",
        "bitkan",
        "bitmart",
        "bitmex",
        "bitpay",
        "bitpie",
        "bitstamp",
        "bittrex",
        "bitvavo",
        "bitvenus",
        "blockfi",
        "blofin-exchange",
        "btcturk",
        "btse",
        "bullish",
        "canary-exchange",
        "catex",
        "celsius-network",
        "cex-io",
        "changenow",
        "cobinhood",
        "coin-list",
        "coinbase",
        "coincheck",
        "coindcx",
        "coinex",
        "coinhako",
        "coinify",
        "coinjar",
        "coinlist",
        "coinmetro",
        "coinone",
        "coinsbit",
        "coinspaid",
        "coinspot",
        "coinsquare",
        "coinstore",
        "coinw",
        "coinzix",
        "coss-io",
        "crex24",
        "crypto-com",
        "delta-exchange",
        "deribit",
        "dex-trade",
        "difx",
        "digifinex",
        "digital-surge",
        "dumpex",
        "etoro",
        "fairdesk",
        "fastex",
        "firi",
        "ftx",
        "gate",
        "gate-io",
        "gbx",
        "gemini",
        "gmo-coin",
        "hitbtc",
        "hoo-com",
        "hotbit",
        "indodax",
        "kanga",
        "korbit",
        "kraken",
        "kryptono",
        "kucoin",
        "latoken",
        "liquid",
        "maskex",
        "mexc",
        "nacdaq",
        "nexo",
        "nifty-gateway",
        "okx",
        "oobit",
        "paribu",
        "phemex",
        "poloniex",
        "quadrigacx",
        "remitano",
        "revolut",
        "shakepay",
        "shapeshift",
        "swipe-io",
        "tagz",
        "tidex",
        "topbtc",
        "trade-io",
        "upbit",
        "uphold",
        "wirex",
        "yunbi",
        "zb-com",
        # stablecoin issuers / institutional ramps
        "circle",
        "paxos",
        # bridges (named; most are contracts, kept as belt-and-braces)
        "across-protocol",
        "allbridge",
        "axelar",
        "celer-network",
        "connext",
        "cross-chain",
        "debridge",
        "hop-protocol",
        "interport-finance",
        "layerzero",
        "multichain",
        "optics",
        "optimism-bridge",
        "rhino-fi",
        "stargate",
        "synapse",
        "wormhole",
        "xy-finance",
        # account-abstraction infra: bundlers/paymasters/relayers first-fund
        # fresh smart wallets by design — the canonical unlabeled-hub shape
        "erc-4337-bundler",
        "paymaster",
        "pimlico",
        "stackup",
        "zerodev",
        "candide-wallet",
        "etherspot",
        "biconomy",
        "biconomy-com",
        "gelato",
        "alchemy",
        # mining pools (payout wallets fund many users)
        "f2pool",
        "miningpoolhub",
    }
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", help="local accounts.csv (skips the download)")
    args = parser.parse_args()

    if args.csv:
        text = Path(args.csv).read_text()
    else:
        print(f"downloading {SOURCE_URL} ...", file=sys.stderr)
        with urllib.request.urlopen(SOURCE_URL, timeout=120) as response:
            text = response.read().decode()

    matched: set[str] = set()
    label_hits: Counter[str] = Counter()
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        label = (row.get("label") or "").strip()
        address = (row.get("address") or "").strip().lower()
        if label in HUB_LABELS and address.startswith("0x") and len(address) == 42:
            matched.add(address)
            label_hits[label] += 1

    unused = sorted(HUB_LABELS - set(label_hits))
    if unused:
        print(f"note: {len(unused)} hub labels matched nothing: {unused}", file=sys.stderr)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    header = (
        f"# hub funding addresses — generated {datetime.now(UTC).date()} by\n"
        f"# scripts/build_hub_labels.py from {SOURCE_URL}\n"
        f"# source dataset: eth-labels (MIT, github.com/dawsbot/eth-labels)\n"
        f"# {len(matched)} addresses across {len(label_hits)} labels\n"
    )
    body = "\n".join(sorted(matched)) + "\n"
    with gzip.open(OUT_PATH, "wt", encoding="utf-8", compresslevel=9) as fh:
        fh.write(header + body)
    print(f"wrote {len(matched)} addresses -> {OUT_PATH}", file=sys.stderr)
    for label, count in label_hits.most_common(15):
        print(f"  {label}: {count}", file=sys.stderr)


if __name__ == "__main__":
    main()
