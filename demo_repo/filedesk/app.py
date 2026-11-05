"""FileDesk web service (needs Flask; not imported by the tests)."""
from flask import Flask, jsonify, request

from filedesk.tools import file_size, read_upload

app = Flask(__name__)


@app.get("/size")
def size():
    name = request.args.get("name", "")
    return jsonify({"name": name, "bytes": file_size(name)})


@app.get("/preview")
def preview():
    name = request.args.get("name", "")
    return jsonify({"name": name, "text": read_upload(name)})
