"""Detection engine.

Runs a stream of normalized :class:`LogEvent` through signature rules
(single-event) and stateful rules (aggregating across events) to produce
alerts. Rule thresholds are configurable; defaults are tuned for low noise.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from ..models import Severity
from .events import LogEvent, enrich_web_attacks
from .models import Alert, BRUTE_CONTROLS, SOC_CONTROLS, alert_id

SUSPICIOUS_SUDO = re.compile(
    r"(?i)(?:/tmp/|/dev/shm/|\bnc\b|\bncat\b|\bwget\b|\bcurl\b|bash\s+-i|/dev/tcp/|chmod\s+777|chattr)")


@dataclass
class DetectionConfig:
    brute_force_threshold: int = 5     # failed logins from one IP
    spray_user_threshold: int = 5      # distinct users failed from one IP


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()

    def run(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        # stateful accumulators
        failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        failed_users_by_ip: dict[str, set] = defaultdict(set)
        success_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

        for ev in events:
            # -- signature (single-event) rules --
            if ev.event_type == "sudo_command":
                cmd = ev.fields.get("cmd", ev.message)
                if SUSPICIOUS_SUDO.search(cmd):
                    alerts.append(Alert(
                        id="", rule="sudo-suspicious-command",
                        title=f"Suspicious sudo command by {ev.user or 'unknown'}",
                        severity=Severity.MEDIUM,
                        entities={k: v for k, v in ev.entities().items()},
                        description=f"sudo executed a suspicious command: {cmd.strip()[:200]}",
                        event_evidence_ids=[ev.evidence_id], controls=list(SOC_CONTROLS),
                    ))
            if ev.event_type == "group_change":
                alerts.append(Alert(
                    id="", rule="privileged-group-change",
                    title=f"User added to privileged group '{ev.fields.get('grp', '?')}'",
                    severity=Severity.HIGH, entities=ev.entities(),
                    description=ev.message[:200],
                    event_evidence_ids=[ev.evidence_id],
                    controls=SOC_CONTROLS + ["NIST:AC-2"],
                ))
            if ev.event_type in ("web_request", "generic"):
                for attack in enrich_web_attacks(ev):
                    alerts.append(Alert(
                        id="", rule=f"web-attack-{attack}",
                        title=f"Web attack signature ({attack}) from {ev.src_ip or 'unknown'}",
                        severity=Severity.HIGH, entities=ev.entities(),
                        description=f"{attack} pattern in request: {ev.message[:200]}",
                        event_evidence_ids=[ev.evidence_id],
                        controls=SOC_CONTROLS + ["OWASP:A03"] if attack == "sqli"
                        else list(SOC_CONTROLS),
                    ))

            # -- accumulate for stateful rules --
            if ev.event_type in ("ssh_login_failed", "ssh_invalid_user"):
                if ev.src_ip:
                    failed_by_ip[ev.src_ip].append(ev)
                    if ev.user:
                        failed_users_by_ip[ev.src_ip].add(ev.user)
            elif ev.event_type == "ssh_login_success" and ev.src_ip:
                success_by_ip[ev.src_ip].append(ev)

        # -- stateful rules (evaluated after the stream) --
        for ip, fails in failed_by_ip.items():
            if len(fails) >= self.config.brute_force_threshold:
                distinct_users = failed_users_by_ip[ip]
                spray = len(distinct_users) >= self.config.spray_user_threshold
                evidence_ids = sorted({f.evidence_id for f in fails if f.evidence_id})
                if spray:
                    alerts.append(Alert(
                        id="", rule="password-spray",
                        title=f"Password spray from {ip} ({len(fails)} failures, {len(distinct_users)} users)",
                        severity=Severity.HIGH, entities={"ip": ip},
                        description=f"{len(fails)} failed logins across {len(distinct_users)} distinct users from {ip}.",
                        event_evidence_ids=evidence_ids, count=len(fails),
                        controls=list(BRUTE_CONTROLS),
                    ))
                else:
                    alerts.append(Alert(
                        id="", rule="ssh-brute-force",
                        title=f"SSH brute force from {ip} ({len(fails)} failures)",
                        severity=Severity.HIGH, entities={"ip": ip},
                        description=f"{len(fails)} failed SSH logins from {ip} exceeded the threshold.",
                        event_evidence_ids=evidence_ids, count=len(fails),
                        controls=list(BRUTE_CONTROLS),
                    ))
                # brute force followed by a success from the same IP = likely compromise
                if ip in success_by_ip:
                    succ = success_by_ip[ip]
                    users = sorted({s.user for s in succ if s.user})
                    alerts.append(Alert(
                        id="", rule="successful-login-after-bruteforce",
                        title=f"Successful login from {ip} after {len(fails)} failures (possible compromise)",
                        severity=Severity.CRITICAL,
                        entities={"ip": ip, **({"user": users[0]} if users else {})},
                        description=(
                            f"{ip} authenticated successfully as {', '.join(users) or 'a user'} "
                            f"after {len(fails)} failed attempts — treat as a suspected breach."
                        ),
                        event_evidence_ids=sorted(evidence_ids + [s.evidence_id for s in succ if s.evidence_id]),
                        count=len(fails),
                        controls=BRUTE_CONTROLS + ["NIST:IR-4"],
                    ))
        for a in alerts:
            a.id = alert_id(a.rule, a.entities)
        deduped = {a.id: a for a in alerts}
        return list(deduped.values())
