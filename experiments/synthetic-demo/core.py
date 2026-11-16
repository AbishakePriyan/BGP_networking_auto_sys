"""Shared feature extraction and FRR control for this isolated lab only."""
from __future__ import annotations
import ipaddress
import json
from json import decoder
from pathlib import Path
import re
import subprocess
import zlib

ROOT = Path(__file__).resolve().parent
FEATURES = ["origin_mismatch", "is_more_specific", "prefix_length_delta",
            "as_path_length", "repeated_as_count"]
PEERS = {"10.199.0.2": "BLOCK-R1", "10.199.0.4": "BLOCK-R3"}


def vty(router: str, commands: list[str]) -> str:
    if router not in {"r1", "r2", "r3"}:
        raise ValueError("Only the three bgpguard lab routers are allowed")
    args = ["docker", "exec", f"bgpguard-v2-{router}", "vtysh"]
    for command in commands:
        args.extend(["-c", command])
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    output = result.stdout + result.stderr
    if result.returncode or any(x in output.lower() for x in
                               ["unknown command", "ambiguous command", "failed to connect"]):
        raise RuntimeError(output.strip() or f"vtysh exited {result.returncode}")
    return output


def routes() -> list[dict]:
    raw = vty("r2", ["show bgp ipv4 unicast json"])
    start = raw.find("{")
    if start < 0:
        raise RuntimeError(f"FRR returned no JSON: {raw}")
    decoder = json.JSONDecoder()
    data, _ = decoder.raw_decode(raw[start:])
    return parse_routes(data)


def parse_routes(table: dict) -> list[dict]:
    if "routes" not in table or not isinstance(table["routes"], dict):
        raise ValueError("Unexpected FRR JSON structure: expected a 'routes' object")
    result = []
    for prefix, paths in table["routes"].items():
        if not isinstance(paths, list):
            raise ValueError("Unexpected FRR JSON path structure")
        for path in paths:
            # The lab uses direct, numbered eBGP peers and simple AS_SEQUENCE paths.
            peer = path.get("peerId")
            if peer not in PEERS:
                peer = next((hop.get("ip") for hop in path.get("nexthops", [])
                             if hop.get("ip") in PEERS), None)
            as_path = path.get("path", "")
            if isinstance(as_path, dict):
                as_path = as_path.get("string", "")
            if not peer or not isinstance(as_path, str) or not re.fullmatch(r"\d+(?:\s+\d+)*", as_path.strip()):
                continue
            ases = [int(x) for x in as_path.split()]
            result.append({"prefix": str(ipaddress.ip_network(prefix)), "peer": peer,
                           "as_path": ases, "origin_as": ases[-1]})
    return result


def extract(route: dict, registry: dict) -> dict | None:
    network = ipaddress.ip_network(route["prefix"])
    candidates = [(ipaddress.ip_network(prefix), allowed)
                  for prefix, allowed in registry.items()
                  if network.subnet_of(ipaddress.ip_network(prefix))]
    if not candidates:
        return None  # Unknown ownership is not automatically malicious.
    covering, allowed = max(candidates, key=lambda item: item[0].prefixlen)
    delta = network.prefixlen - covering.prefixlen
    path = route["as_path"]
    return {"origin_mismatch": int(route["origin_as"] not in allowed),
            "is_more_specific": int(delta > 0), "prefix_length_delta": delta,
            "as_path_length": len(path), "repeated_as_count": len(path) - len(set(path))}


def signature(route: dict) -> tuple:
    return route["prefix"], route["peer"], tuple(route["as_path"])


def filter_commands(peer: str, prefix: str) -> list[str]:
    if peer not in PEERS:
        raise ValueError("Unknown peer: refusing to configure a router")
    network = ipaddress.ip_network(prefix, strict=True)
    # Restrict this demonstration to the documented lab prefix and its subnets.
    if not network.subnet_of(ipaddress.ip_network("10.199.113.0/24")):
        raise ValueError("Prefix outside the lab: refusing mitigation")
    seq = 10000 + zlib.crc32(str(network).encode()) % 100000000
    # Permit in the prefix-list means MATCH the deny clause of the route-map.
    return ["configure terminal",
            f"ip prefix-list {PEERS[peer]} seq {seq} permit {network}",
            "end", f"clear bgp {peer} soft in"]


def reset_commands() -> list[str]:
    commands = ["configure terminal"]
    for name in PEERS.values():
        commands.extend([f"no ip prefix-list {name}",
                         f"ip prefix-list {name} seq 9999 permit 192.0.2.255/32"])
    commands.append("end")
    commands.extend(f"clear bgp {peer} soft in" for peer in PEERS)
    return commands
