"""FileDesk web service (needs Flask; not imported by the tests)."""
from flask import Flask, jsonify, request

from filedesk.tools import file_size

app = Flask(__name__)


@app.get("/size")
def size():
    name = request.args.get("name", "")
    return jsonify({"name": name, "bytes": file_size(name)})
