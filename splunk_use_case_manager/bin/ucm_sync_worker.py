"""Modular input that executes queued and scheduled content sync jobs.

Emits no events. Reads the modular-input configuration from stdin to obtain
the session key (see README/inputs.conf.spec).
"""

import os
import sys
import xml.etree.ElementTree as ET  # nosec - parses splunkd-supplied configuration only

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from splunk_ucm.config import load_config  # noqa: E402
from splunk_ucm.content.registry import remote_provider  # noqa: E402
from splunk_ucm.content.worker import SyncWorker  # noqa: E402
from splunk_ucm.discovery.worker import DiscoveryWorker  # noqa: E402
from splunk_ucm.readiness.worker import ReadinessWorker  # noqa: E402
from splunk_ucm.errors import StorageError  # noqa: E402
from splunk_ucm.log import get_logger  # noqa: E402
from splunk_ucm.platform.capabilities import PlatformProbe  # noqa: E402
from splunk_ucm.secrets import get_secret  # noqa: E402
from splunk_ucm.storage.kvstore import KVStore  # noqa: E402
from splunk_ucm.storage.transport import SimpleRequestTransport  # noqa: E402

log = get_logger("splunk_ucm.worker")

SCHEME = """<scheme>
  <title>Use Case Manager content sync worker</title>
  <description>Executes queued and scheduled content synchronization jobs. Emits no events.</description>
  <use_external_validation>false</use_external_validation>
  <use_single_instance>false</use_single_instance>
  <streaming_mode>simple</streaming_mode>
  <endpoint>
    <args>
      <arg name="max_jobs_per_run">
        <title>Maximum jobs per run</title>
        <data_type>number</data_type>
        <required_on_create>false</required_on_create>
      </arg>
    </args>
  </endpoint>
</scheme>
"""


def _session_key(config_xml: str) -> str:
    root = ET.fromstring(config_xml)  # nosec
    node = root.find("session_key")
    return node.text.strip() if node is not None and node.text else ""


def _max_jobs(config_xml: str) -> int:
    root = ET.fromstring(config_xml)  # nosec
    for param in root.iter("param"):
        if param.get("name") == "max_jobs_per_run" and param.text:
            try:
                return max(1, min(10, int(param.text.strip())))
            except ValueError:
                return 1
    return 1


def _leader(probe: PlatformProbe):
    member = probe.is_shc_member()
    if member is None:
        return None
    if not member:
        return True
    return probe.is_shc_captain()


def run(config_xml: str) -> int:
    key = _session_key(config_xml)
    if not key:
        log.error("no session key supplied to worker")
        return 1
    transport = SimpleRequestTransport(key)
    probe = PlatformProbe(transport)
    config = load_config(transport)
    store = KVStore(transport)
    leader = lambda: _leader(probe)
    workers = [
        ("sync", SyncWorker(store, config, remote_provider,
                            lambda: get_secret(transport, "github_token") or "", leader)),
        ("discovery", DiscoveryWorker(store, config, transport, leader)),
        ("readiness", ReadinessWorker(store, config, leader)),
    ]
    for _ in range(_max_jobs(config_xml)):
        ran = False
        for name, worker in workers:
            result = worker.run_once()
            if result.get("action") == "skipped":
                return 0
            if result.get("action") != "idle":
                log.info("%s worker run" % name, extra=result)
                ran = True
                break
        if not ran:
            break
    return 0


def main(argv) -> int:
    if len(argv) > 1 and argv[1] == "--scheme":
        sys.stdout.write(SCHEME)
        return 0
    if len(argv) > 1 and argv[1] == "--validate-arguments":
        return 0
    try:
        return run(sys.stdin.read())
    except StorageError as exc:
        if exc.status == 503:
            log.warning("kvstore not ready; worker will retry on next interval")
            return 0
        log.exception("worker storage failure")
        return 1
    except Exception:
        log.exception("worker crashed")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
