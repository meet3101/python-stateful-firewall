import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from rules import RuleEngine

def test_allow_port_80():
    engine = RuleEngine("config/rules.yaml")
    assert engine.match({"proto": "tcp", "dst_port": 80, "src": "1.2.3.4"}) == "allow"

def test_default_deny():
    engine = RuleEngine("config/rules.yaml")
    assert engine.match({"proto": "tcp", "dst_port": 9999, "src": "1.2.3.4"}) == "deny"