"""Flask API + web UI. Run: pip install -r requirements.txt ; python app.py ; open http://127.0.0.1:5000"""
from flask import Flask, jsonify, request, send_file
from chain import Network, USERS, ROLE_STAGES, STAGES, MAX_TEMP

app = Flask(__name__)
net = Network()

def state():
    return dict(nodes=net.status(), products=net.products(), users=USERS, role_stages=ROLE_STAGES, stages=STAGES,
                max_temp=MAX_TEMP, chains=[[b.to_dict() for b in n.chain] for n in net.nodes])

@app.get("/")
def home(): return send_file("index.html")

@app.get("/api/state")
def get_state(): return jsonify(state())

@app.post("/api/event")
def event():
    d = request.get_json()
    try:
        e = dict(product=(d.get("product") or "").strip(), stage=d.get("stage"), user=d.get("user"), location=d.get("location") or "")
        if not e["product"]: raise ValueError("Product ID is required")
        if d.get("temp") not in (None, ""): e["temp"] = float(d["temp"])
        net.submit(int(d.get("node", 0)), e)
    except (ValueError, KeyError, IndexError) as ex:
        return jsonify(error=str(ex)), 400
    return jsonify(state())

@app.post("/api/tamper")
def tamper():
    d = request.get_json()
    try: net.nodes[int(d["node"])].chain[int(d["index"])].event[d["field"]] = d["value"]
    except (ValueError, KeyError, IndexError): return jsonify(error="Pick an existing block"), 400
    net.save(); return jsonify(state())

@app.post("/api/heal")
def heal():
    try: net.heal()
    except ValueError as ex: return jsonify(error=str(ex)), 400
    return jsonify(state())

@app.post("/api/reset")
def reset(): net.reset(); return jsonify(state())

@app.get("/api/trace/<product>")
def trace(product):
    best = net.best()
    if not best: return jsonify([])
    out = []
    for x in best.chain[1:]:
        if x.event["product"] == product:
            conf = sum(1 for n in net.nodes if n.valid()[0] and len(n.chain) > x.index and n.chain[x.index].hash == x.hash)
            out.append(dict(index=x.index, confirmations=conf, nodes=len(net.nodes),
                            **{k: v for k, v in x.event.items() if k != "sig"}))
    return jsonify(out)

if __name__ == "__main__": app.run(debug=True)
