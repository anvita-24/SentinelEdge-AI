"""MQTT ingestion worker (batching) + signed-command publisher."""
import json
import logging
import queue
import threading
from typing import Callable

from .config import settings

log = logging.getLogger("sentineledge.mqtt")
TELEMETRY_TOPIC = "sentineledge/telemetry/#"
_pub = None  # paho client used for publishing commands


def publish_command(device_id: str, cmd: dict) -> bool:
    if _pub is None:
        return False
    try:
        return _pub.publish(f"sentineledge/devices/{device_id}/cmd", json.dumps(cmd), qos=1).rc == 0
    except Exception:  # pragma: no cover
        return False


class Ingestor:
    """Subscribes to telemetry, buffers events and flushes them in batches."""

    def __init__(self, handler: Callable[[list], None], batch: int = 200, flush_s: float = 0.5):
        self.q: queue.Queue = queue.Queue(maxsize=100_000)
        self.handler, self.batch, self.flush_s = handler, batch, flush_s
        self.stop = threading.Event()
        self.client = None

    def start(self) -> None:  # pragma: no cover - needs a broker
        global _pub
        import paho.mqtt.client as mqtt
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sentineledge-ingest")
        c.on_connect = lambda cl, u, f, rc, p=None: cl.subscribe(TELEMETRY_TOPIC, qos=0)
        c.on_message = self._on_message
        c.connect_async(settings.mqtt_host, settings.mqtt_port, keepalive=30)
        c.loop_start()
        self.client, _pub = c, c
        threading.Thread(target=self._worker, daemon=True, name="ingest-worker").start()

    def _on_message(self, _c, _u, msg) -> None:
        try:
            self.q.put_nowait(json.loads(msg.payload))
        except (ValueError, queue.Full):
            log.warning("dropped malformed/overflow message on %s", msg.topic)

    def _worker(self) -> None:  # pragma: no cover
        while not self.stop.is_set():
            buf = []
            try:
                buf.append(self.q.get(timeout=self.flush_s))
                while len(buf) < self.batch:
                    buf.append(self.q.get_nowait())
            except queue.Empty:
                pass
            if buf:
                try:
                    self.handler(buf)
                except Exception:
                    log.exception("batch failed")

    def close(self) -> None:  # pragma: no cover
        self.stop.set()
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
