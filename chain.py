"""Multi-node supply chain blockchain: ECDSA signatures, roles, business rules,
consensus (heal from best valid chain) and JSON persistence."""
import copy, hashlib, json, os, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGES = ["Harvested", "Processed", "Shipped", "Delivered"]
ROLE_STAGES = {"Farmer": ["Harvested"], "Processor": ["Processed"], "Shipper": ["Shipped"], "Retailer": ["Delivered"]}
USERS = {"Wayanad Farm": "Farmer", "Palakkad Mill": "Processor", "Cochin Logistics": "Shipper", "Bengaluru Mart": "Retailer"}
MAX_TEMP = 35

class Keys:
    """One ECDSA (P-256) key pair per participant. Private keys are kept in keys.json (demo only)."""
    def __init__(self, path="keys.json"):
        data = json.load(open(path)) if os.path.exists(path) else {}
        self.priv = {u: serialization.load_pem_private_key(data[u].encode(), None) if u in data
                     else ec.generate_private_key(ec.SECP256R1()) for u in USERS}
        pem = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
        json.dump({u: pem(k) for u, k in self.priv.items()}, open(path, "w"))
    def sign(self, user, msg):
        return self.priv[user].sign(msg.encode(), ec.ECDSA(hashes.SHA256())).hex()
    def verify(self, user, msg, sig):  # verification only needs the PUBLIC key
        try:
            self.priv[user].public_key().verify(bytes.fromhex(sig), msg.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, KeyError):
            return False

KEYS = Keys()
payload = lambda e: json.dumps({k: v for k, v in e.items() if k != "sig"}, sort_keys=True)

class Block:
    def __init__(self, index, event, prev_hash, t=None, nonce=0, hash=""):
        self.index, self.event, self.prev_hash, self.nonce, self.hash = index, event, prev_hash, nonce, hash
        self.time = t if t is not None else time.time()
    def calc(self):
        body = json.dumps([self.index, self.time, self.event, self.prev_hash, self.nonce], sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()
    def mine(self, d):
        while not (h := self.calc()).startswith("0" * d):
            self.nonce += 1
        self.hash = h
    def to_dict(self):
        return dict(index=self.index, event=self.event, prev_hash=self.prev_hash, t=self.time, nonce=self.nonce, hash=self.hash)

def check_rules(prior, e):
    """Business rules: known participant, role may record this stage, stages in order."""
    role = USERS.get(e.get("user"))
    if not role: return "Unknown participant"
    if e.get("stage") not in ROLE_STAGES[role]: return f"A {role} cannot record '{e.get('stage')}'"
    n = sum(1 for b in prior[1:] if b.event["product"] == e["product"])
    want = STAGES[n] if n < len(STAGES) else None
    if e["stage"] != want: return f"Stage out of order: expected {want or 'nothing (journey complete)'}"

def validate(chain, d):
    """Returns (ok, first_bad_index, reason)."""
    for i, b in enumerate(chain):
        if b.hash != b.calc() or not b.hash.startswith("0" * d): return False, i, "Hash or proof-of-work invalid"
        if i == 0: continue
        if b.prev_hash != chain[i - 1].hash: return False, i, "Broken link to previous block"
        if not KEYS.verify(b.event.get("user"), payload(b.event), b.event.get("sig", "")): return False, i, "Invalid signature"
        err = check_rules(chain[:i], b.event)
        if err: return False, i, err
    return True, None, ""

class Node:
    def __init__(self, name, d):
        self.name, self.d = name, d
        g = Block(0, {"product": "-", "stage": "Genesis", "user": "System"}, "0" * 64, t=0.0)
        g.mine(d); self.chain = [g]
    def valid(self): return validate(self.chain, self.d)
    def build(self, e):
        err = check_rules(self.chain, e)
        if err: raise ValueError(err)
        e = dict(e); e["sig"] = KEYS.sign(e["user"], payload(e))
        b = Block(len(self.chain), e, self.chain[-1].hash); b.mine(self.d); return b
    def receive(self, b):
        trial = self.chain + [b]
        if b.prev_hash == self.chain[-1].hash and validate(trial, self.d)[0]:
            self.chain = trial; return True
        return False

class Network:
    def __init__(self, n=3, d=3, path="chain_data.json"):
        self.d, self.path = d, path
        self.nodes = [Node(f"Node {i + 1}", d) for i in range(n)]
        if os.path.exists(path):
            saved = json.load(open(path)).get("chain")
            if saved:
                for node in self.nodes: node.chain = [Block(**x) for x in saved]
    def save(self):
        """Persist only the best VALID chain, so a simulated attack never survives a restart."""
        best = self.best()
        if best: json.dump({"chain": [b.to_dict() for b in best.chain]}, open(self.path, "w"))
    def reset(self):
        if os.path.exists(self.path): os.remove(self.path)
        self.nodes = [Node(n.name, self.d) for n in self.nodes]
    def best(self):
        ok = [n for n in self.nodes if n.valid()[0]]
        return max(ok, key=lambda n: len(n.chain)) if ok else None
    def submit(self, idx, e):
        node = self.nodes[idx]
        if not node.valid()[0]: raise ValueError("This node's chain is invalid. Heal the network first.")
        b = node.build(e); node.chain.append(b)
        for i, n in enumerate(self.nodes):
            if i != idx: n.receive(copy.deepcopy(b))   # broadcast; every peer re-validates
        self.save(); return b
    def heal(self):
        best = self.best()
        if not best: raise ValueError("No valid chain exists on any node")
        for n in self.nodes:
            if n is not best and (not n.valid()[0] or len(n.chain) < len(best.chain)):
                n.chain = copy.deepcopy(best.chain)
        self.save()
    def status(self):
        best = self.best(); tip = best.chain[-1].hash if best else None
        out = []
        for n in self.nodes:
            ok, bad, why = n.valid()
            out.append(dict(name=n.name, length=len(n.chain), valid=ok, bad_index=bad, reason=why,
                            tip=n.chain[-1].hash[:12], agrees=ok and n.chain[-1].hash == tip))
        return out
    def products(self):
        best, res = self.best(), {}
        for x in (best.chain[1:] if best else []):
            e = x.event
            p = res.setdefault(e["product"], dict(product=e["product"], events=0, alerts=0))
            p.update(stage=e["stage"], handler=e["user"], done=e["stage"] == STAGES[-1])
            p["events"] += 1; p["alerts"] += e.get("temp", 0) > MAX_TEMP
        return list(res.values())