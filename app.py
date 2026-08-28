"""
Small local web UI for the URL checker.

Run with:  python app.py
Then open: http://127.0.0.1:5000
"""
from flask import Flask, jsonify, render_template, request

from aggregator import check_url

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
    report = check_url(url)
    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
