#!/usr/bin/env python3
"""Wazuh custom integration: forward an alert file to the Sidecar API.

Wazuh invokes integrations as: script alert_file api_key hook_url
Copy this file to /var/ossec/integrations/custom-wazuh-sidecar.py and make it
executable. It deliberately only uses the Python standard library.
"""

import json
import sys
import urllib.error
import urllib.request


def main() -> int:
    if len(sys.argv) < 4:
        print("Usage: custom-wazuh-sidecar.py <alert_file> <api_key> <sidecar_url>", file=sys.stderr)
        return 2
    alert_file, api_key, sidecar_url = sys.argv[1:4]
    with open(alert_file, "rb") as source:
        alert = json.load(source)
    request = urllib.request.Request(
        sidecar_url.rstrip("/") + "/v1/alerts",
        data=json.dumps(alert).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return 0 if 200 <= response.status < 300 else 1
    except (urllib.error.URLError, urllib.error.HTTPError) as error:
        print("Wazuh Sidecar delivery failed: {0}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
