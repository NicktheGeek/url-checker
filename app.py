"""
Small local web UI for the URL checker.

Run with:  python app.py
Then open: http://127.0.0.1:5050

(Port 5000 is skipped because macOS's AirPlay Receiver claims it by default.)
"""
import csv
import io
import json

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

import history
from aggregator import check_url, check_url_streaming

app = Flask(__name__)


def _normalize_url(raw: str) -> str:
    url = (raw or "").strip()
    if url and not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
    return url


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    """One-shot check: waits for every source, returns the full report.
    Kept for API compatibility -- the UI itself uses /check/stream so fast
    sources show up before slow ones (VirusTotal, urlscan.io) finish."""
    data = request.get_json(silent=True) or {}
    url = _normalize_url(data.get("url"))
    if not url:
        return jsonify({"error": "Please provide a URL"}), 400
    report = check_url(url)
    history.save_report(report)
    return jsonify(report)


@app.route("/check/stream", methods=["POST"])
def check_stream():
    """Server-Sent Events version of /check: emits a `result` event per
    source as it finishes, then one `done` event with the full report."""
    data = request.get_json(silent=True) or {}
    url = _normalize_url(data.get("url"))
    if not url:
        return jsonify({"error": "Please provide a URL"}), 400

    def generate():
        for kind, payload in check_url_streaming(url):
            if kind == "done":
                report_id = history.save_report(payload)
                payload = {**payload, "id": report_id}
            yield _sse(kind, payload)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/check/batch/stream", methods=["POST"])
def check_batch_stream():
    """SSE stream for checking a list of URLs one at a time (each URL's own
    sources still run in parallel). Events carry an `index` so the frontend
    knows which URL a `result`/`item-done` belongs to."""
    data = request.get_json(silent=True) or {}
    raw_urls = data.get("urls") or []
    urls = [_normalize_url(u) for u in raw_urls if (u or "").strip()]

    def generate():
        yield _sse("start", {"total": len(urls)})
        summary = {"SUSPICIOUS": 0, "NO ISSUES FOUND": 0, "NO DATA": 0}
        for index, url in enumerate(urls):
            yield _sse("item-start", {"index": index, "url": url})
            for kind, payload in check_url_streaming(url):
                if kind == "result":
                    yield _sse("result", {"index": index, "result": payload})
                else:
                    report_id = history.save_report(payload)
                    payload = {**payload, "id": report_id}
                    summary[payload["verdict"]] = summary.get(payload["verdict"], 0) + 1
                    yield _sse("item-done", {"index": index, "report": payload})
        yield _sse("done", {"summary": summary})

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/history")
def history_list():
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(history.list_history(limit=limit))


@app.route("/history/<int:report_id>")
def history_detail(report_id):
    report = history.get_report(report_id)
    if report is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(report)


@app.route("/history/<int:report_id>", methods=["DELETE"])
def history_delete(report_id):
    deleted = history.delete_report(report_id)
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@app.route("/history/<int:report_id>/export.csv")
def history_export_csv(report_id):
    report = history.get_report(report_id)
    if report is None:
        return jsonify({"error": "Not found"}), 404

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["service", "status", "summary", "link"])
    for r in report["results"]:
        writer.writerow([r["service"], r["status"], r["summary"], r.get("link", "")])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="url-check-{report_id}.csv"'},
    )


if __name__ == "__main__":
    app.run(debug=True, port=5050, threaded=True)
