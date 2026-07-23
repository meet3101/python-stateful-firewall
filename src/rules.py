import yaml
import ipaddress

class RuleEngine:
    def __init__(self, config_path):
        with open(config_path) as f:
            self.rules = yaml.safe_load(f)["rules"]

    def match(self, pkt_info):
        for rule in self.rules:
            if self._rule_matches(rule, pkt_info):
                return rule["action"]
        return "deny"  # default deny

    def _rule_matches(self, rule, pkt_info):
        if "proto" in rule and rule["proto"] != pkt_info["proto"]:
            return False
        if "dst_port" in rule and rule["dst_port"] != pkt_info.get("dst_port"):
            return False
        if "src" in rule:
            if ipaddress.ip_address(pkt_info["src"]) not in ipaddress.ip_network(rule["src"]):
                return False
        return True