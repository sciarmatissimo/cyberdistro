"""Overall status colour. Decided ONLY from layer-2 incidents and engine health.

  GREY    monitoring inactive or incomplete (an engine silent / not running)
  RED     at least one open, CONFIRMED, high-severity incident in the window
  YELLOW  any other open medium/high incident in the window
  GREEN   nothing significant detected — never a guarantee of safety
"""

from __future__ import annotations

from dataclasses import dataclass

GREEN, YELLOW, RED, GREY = "verde", "giallo", "rosso", "grigio"


@dataclass
class Health:
    suricata: bool
    zeek: bool
    sensor: bool
    network: bool

    @property
    def ok(self) -> bool:
        return self.suricata and self.zeek and self.sensor and self.network

    def missing(self) -> list[str]:
        return [n for n, v in (("rete", self.network), ("Suricata", self.suricata),
                               ("Zeek", self.zeek), ("sensore", self.sensor)) if not v]


def decide(incidents: list[dict], health: Health, now: float, window: float = 3600.0) -> dict:
    recent = [i for i in incidents if i.get("status", "aperto") == "aperto" and now - i["last_ts"] <= window]
    red = [i for i in recent if i["level"] == "confermato" and i["severity"] == "alta"]
    yellow = [i for i in recent if i not in red and i["severity"] in ("media", "alta")]
    low = [i for i in recent if i["severity"] == "bassa"]
    if not health.ok:
        colour = GREY
    elif red:
        colour = RED
    elif yellow:
        colour = YELLOW
    else:
        colour = GREEN
    return {"colour": colour, "red": len(red), "yellow": len(yellow), "info": len(low),
            "missing": health.missing(), "updated": now,
            "last": max((i["last_ts"] for i in recent if i["severity"] != "bassa"), default=None)}
