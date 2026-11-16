"""Commands for the three-container BGPGuard demonstration."""
import argparse
import json
import subprocess
from core import vty, reset_commands, routes


def attack(enabled):
    command = "network 10.199.113.0/25" if enabled else "no network 10.199.113.0/25"
    print(vty("r3", ["configure terminal", "router bgp 65003",
                     "address-family ipv4 unicast", command, "end"]))
    print("Attack announcement", "ENABLED" if enabled else "WITHDRAWN")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["status", "attack-on", "attack-off", "reset", "ping", "paths", "filters"])
    action = parser.parse_args().action
    if action == "status":
        print(vty("r2", ["show bgp ipv4 unicast summary", "show bgp ipv4 unicast", "show ip route"]))
    elif action == "paths":
        print(json.dumps(routes(), indent=2))
    elif action == "attack-on":
        attack(True)
    elif action == "attack-off":
        attack(False)
    elif action == "reset":
        attack(False)
        print(vty("r2", reset_commands()))
        print("Attack withdrawn and both lab block lists reset. Logs retained.")
    elif action == "filters":
        print(vty("r2", ["show ip prefix-list BLOCK-R3", "show route-map GUARD-R3"]))
    elif action == "ping":
        result = subprocess.run(["docker", "exec", "bgpguard-v2-r2", "ping", "-c", "3", "-W", "1", "10.199.113.10"])
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
