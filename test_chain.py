import pytest
from chain import Network, validate, STAGES

@pytest.fixture
def net(tmp_path): return Network(d=2, path=str(tmp_path / "c.json"))
ev = lambda stage, user, p="P1", **k: dict(product=p, stage=stage, user=user, location="X", **k)
FLOW = [("Harvested", "Wayanad Farm"), ("Processed", "Palakkad Mill"), ("Shipped", "Cochin Logistics"), ("Delivered", "Bengaluru Mart")]

def run_flow(net, p="P1"):
    for s, u in FLOW: net.submit(0, ev(s, u, p))

def test_full_journey_all_nodes_agree(net):
    run_flow(net)
    assert all(s["valid"] and s["agrees"] and s["length"] == 5 for s in net.status())
    assert net.products()[0]["done"]

def test_wrong_role_rejected(net):
    with pytest.raises(ValueError, match="cannot record"): net.submit(0, ev("Shipped", "Wayanad Farm"))

def test_out_of_order_rejected(net):
    with pytest.raises(ValueError, match="out of order"): net.submit(0, ev("Processed", "Palakkad Mill"))

def test_tamper_detected_and_network_heals(net):
    run_flow(net)
    net.nodes[1].chain[2].event["location"] = "Fake"
    st = net.status()
    assert not st[1]["valid"] and st[1]["bad_index"] == 2 and st[0]["valid"] and st[2]["valid"]
    net.heal()
    assert all(s["valid"] and s["agrees"] for s in net.status())

def test_forged_signature_rejected(net):
    n = net.nodes[0]; b = n.build(ev("Harvested", "Wayanad Farm"))
    b.event["sig"] = "00" * 8; b.mine(n.d)
    ok, i, why = validate(n.chain + [b], n.d)
    assert not ok and why == "Invalid signature"

def test_alerts_and_persistence(net, tmp_path):
    net.submit(0, ev("Harvested", "Wayanad Farm", temp=40))
    assert net.products()[0]["alerts"] == 1
    again = Network(d=2, path=str(tmp_path / "c.json"))
    assert len(again.nodes[0].chain) == 2 and again.nodes[0].valid()[0]

def test_tampering_is_not_persisted(net, tmp_path):
    net.submit(0, ev("Harvested", "Wayanad Farm"))
    net.nodes[1].chain[1].event["location"] = "Fake"; net.save()
    again = Network(d=2, path=str(tmp_path / "c.json"))
    assert all(s["valid"] and s["agrees"] for s in again.status())