"""Module 3 : statistiques et opérations d'ensembles."""

import re
from collections import defaultdict

from logengine.config import ERROR_LEVELS


def top_items(counts: dict, size: int = 10) -> list:
    """Retourne les plus grands compteurs d'un dictionnaire."""
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return ranked[:size]


def compare_with_blacklist(
    active: set, errors: set, blacklist: frozenset
) -> dict:
    """Applique les quatre opérations d'ensembles à la liste noire."""
    common = active & blacklist
    return {
        "active": len(active),
        "with_errors": len(errors),
        "blacklist": len(blacklist),
        "union": len(active | blacklist),
        "intersection": len(common),
        "difference": len(active - blacklist),
        "symmetric_difference": len(active ^ blacklist),
        "errors_and_blacklist": len(errors & blacklist),
        "blacklisted_active_ips": sorted(common),
    }


class Aggregator:
    """Accumule les statistiques lot après lot.

    La mémoire dépend du nombre d'IP et d'utilisateurs différents, pas du
    nombre de lignes. Avec defaultdict, une clé inconnue démarre à zéro au
    lieu de lever une KeyError.
    """

    def __init__(self) -> None:
        self.active_ips = set()
        self.error_ips = set()
        self.by_level = defaultdict(int)
        self.by_service = defaultdict(int)
        self.by_tag = defaultdict(int)
        self.by_route = defaultdict(int)
        self.by_user = defaultdict(int)
        self.by_ip = defaultdict(int)
        self.errors_by_ip = defaultdict(int)
        self.by_status = defaultdict(int)
        self.by_endpoint = defaultdict(int)
        self.by_port = defaultdict(int)
        self.by_day = defaultdict(int)
        self.errors_by_day = defaultdict(int)
        self.by_hour = defaultdict(int)
        self.firewall_actions = defaultdict(int)

    def update(self, batch: list) -> None:
        """Intègre un lot d'enregistrements."""
        for record in batch:
            ip = record["ip"]
            level = record["level"]
            day = record["timestamp"].strftime("%Y-%m-%d")
            self.active_ips.add(ip)
            self.by_ip[ip] += 1
            self.by_level[level] += 1
            self.by_service[record["service"]] += 1
            self.by_tag[record["tag"]] += 1
            self.by_route[record["route"]] += 1
            self.by_day[day] += 1
            self.by_hour[record["timestamp"].hour] += 1
            if record["user"] is not None:
                self.by_user[record["user"]] += 1
            if level in ERROR_LEVELS:
                self.error_ips.add(ip)
                self.errors_by_ip[ip] += 1
                self.errors_by_day[day] += 1
            self.update_details(record)

    def update_details(self, record: dict) -> None:
        """Intègre les compteurs propres à chaque type de payload."""
        payload = record["payload"]
        if isinstance(payload, tuple):
            self.by_port[payload[1]] += 1
            action = record["extra"].get("action", "UNKNOWN")
            self.firewall_actions[action] += 1
        elif isinstance(payload, dict) and "status" in payload:
            self.by_status[payload["status"]] += 1
            path = payload.get("path", "").split("?")[0]
            self.by_endpoint[re.sub(r"/\d+", "/:id", path)] += 1

    def to_dict(self, blacklist: frozenset) -> dict:
        """Construit le résumé final."""
        statuses = sorted(self.by_status.items())
        return {
            "levels": dict(self.by_level),
            "services": dict(self.by_service),
            "tags": dict(self.by_tag),
            "routes": dict(self.by_route),
            "http_status": {str(k): v for k, v in statuses},
            "firewall_actions": dict(self.firewall_actions),
            "distinct_users": len(self.by_user),
            "top_users": top_items(self.by_user),
            "top_ips": top_items(self.by_ip),
            "top_error_ips": top_items(self.errors_by_ip),
            "top_endpoints": top_items(self.by_endpoint),
            "top_ports": top_items(self.by_port),
            "by_day": dict(sorted(self.by_day.items())),
            "errors_by_day": dict(sorted(self.errors_by_day.items())),
            "by_hour": dict(sorted(self.by_hour.items())),
            "ip_sets": compare_with_blacklist(
                self.active_ips, self.error_ips, blacklist
            ),
        }
