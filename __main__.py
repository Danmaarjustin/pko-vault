import pulumi
import requests
import time

config = pulumi.Config("vault")
vault_addr = config.require("address")

def wait_for_vault(url: str, timeout=60):
    pulumi.log.info(f"Checking Vault health at {url}")
    start = time.time()

    while time.time() - start < timeout:
        try:
            r = requests.get(f"{url}/v1/sys/health", timeout=2)
            if r.status_code in (200, 429, 472):
                pulumi.log.info("Vault is reachable")
                return True
        except Exception:
            pass

        time.sleep(2)

    raise Exception("Vault did not become ready in time")

wait_for_vault(vault_addr)
