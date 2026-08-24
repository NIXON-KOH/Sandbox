from flask import Flask, render_template, abort, request, redirect, url_for
import os
import json
import re
import tempfile
import shutil
from collections import Counter, defaultdict
from werkzeug.utils import secure_filename
from datetime import datetime

import detonate  

app = Flask(__name__)

RESULT_DIR = "Results"


# ============================================================
# Generic helpers
# ============================================================

def read_json(path, default=None):
    """Safely read a JSON file."""
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def read_text(path, default=""):
    """Safely read a text file."""
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


# ============================================================
# Report discovery
# ============================================================

def get_all_reports():
    reports = []
    if not os.path.exists(RESULT_DIR):
        return reports
    for entry in sorted(os.listdir(RESULT_DIR), reverse=True):
        report_dir = os.path.join(RESULT_DIR, entry)
        report_path = os.path.join(report_dir, "metadata.json")
        if not os.path.isfile(report_path):
            continue
        data = read_json(report_path)
        if not isinstance(data, dict):
            continue
        data["folder_name"] = entry
        reports.append(data)
    return reports


# ============================================================
# Strace parsing
# ============================================================
TRACE_LINE_RE = re.compile(
    r"^(?P<pid>\d+)"          # PID
    r"\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)"  # time
    r"\s+"
    r"(?P<body>.*)$"          # rest
)

SYSCALL_RE = re.compile(r"^(?P<syscall>[a-zA-Z_][a-zA-Z0-9_]*)\(")
EXECVE_RE = re.compile(r"execve\(\"(?P<path>[^\"]+)\"")
CHILD_RE = re.compile(r"^(?:clone|clone3|fork|vfork)\(.*\)\s+=\s+(?P<child>\d+)")


def parse_trace(trace_text):
    processes = {}
    parent_children = defaultdict(list)
    all_events = []

    for line_number, line in enumerate(trace_text.splitlines(), start=1):
        if not line.strip():
            continue
        match = TRACE_LINE_RE.match(line)
        if not match:
            continue
        timestamp = match.group("time")
        pid = int(match.group("pid"))
        body = match.group("body")

        syscall_match = SYSCALL_RE.match(body)
        syscall = syscall_match.group("syscall") if syscall_match else "other"

        if pid not in processes:
            processes[pid] = {
                "pid": pid,
                "ppid": None,
                "command": "unknown",
                "syscall_count": 0,
                "syscalls": Counter(),
                "events": [],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "children": [],
            }

        process = processes[pid]
        process["syscall_count"] += 1
        process["syscalls"][syscall] += 1
        process["last_seen"] = timestamp

        exec_match = EXECVE_RE.search(body)
        if exec_match:
            executable = exec_match.group("path")
            process["command"] = os.path.basename(executable) or executable

        event = {
            "line": line_number,
            "time": timestamp,
            "pid": pid,
            "syscall": syscall,
            "text": body,
        }
        process["events"].append(event)
        all_events.append(event)

        child_match = CHILD_RE.match(body)
        if child_match:
            child_pid = int(child_match.group("child"))
            if child_pid > 0:
                parent_children[pid].append(child_pid)

    # Build parent-child relationships
    for parent_pid, children in parent_children.items():
        if parent_pid not in processes:
            continue
        for child_pid in children:
            if child_pid not in processes:
                continue
            processes[child_pid]["ppid"] = parent_pid
            if child_pid not in processes[parent_pid]["children"]:
                processes[parent_pid]["children"].append(child_pid)

    # Convert Counters to dicts
    for process in processes.values():
        process["syscalls"] = dict(sorted(process["syscalls"].items(), key=lambda item: item[1], reverse=True))

    process_list = sorted(processes.values(), key=lambda p: p["pid"])
    roots = [p for p in process_list if p["ppid"] is None]

    return {
        "processes": process_list,
        "events": all_events,
        "process_count": len(process_list),
        "event_count": len(all_events),
        "roots": roots,
    }


# ============================================================
# Filesystem diff processing
# ============================================================

def process_diffs(diffs):
    kind_names = {0: "modified", 1: "added", 2: "deleted"}
    processed = []
    for item in diffs or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("Kind")
        path = item.get("Path", "Unknown")
        processed.append({"path": path, "kind": kind_names.get(kind, str(kind))})
    return processed


# ============================================================
# Network log statistics
# ============================================================

def summarise_network_log(net_logs):
    if not net_logs:
        return {"line_count": 0, "connections": 0}
    lines = [line for line in net_logs.splitlines() if line.strip()]
    connection_keywords = ("CONNECT", "GET ", "POST ", "PUT ", "DNS", "UDP", "TCP", "connection", "connect")
    connections = sum(1 for line in lines if any(kw in line for kw in connection_keywords))
    return {"line_count": len(lines), "connections": connections}


# ============================================================
# Report loading
# ============================================================

def load_report(folder_name):
    target_dir = os.path.join(RESULT_DIR, folder_name)
    target_dir = os.path.abspath(target_dir)
    result_root = os.path.abspath(RESULT_DIR)
    if not target_dir.startswith(result_root + os.sep):
        abort(404)
    if not os.path.isdir(target_dir):
        abort(404)

    meta_path = os.path.join(target_dir, "metadata.json")
    active_report = read_json(meta_path)
    if not isinstance(active_report, dict):
        abort(404)
    active_report["folder_name"] = folder_name

    diff_path = os.path.join(target_dir, "filesystem_diff.json")
    raw_diffs = read_json(diff_path, [])
    diffs = process_diffs(raw_diffs)

    net_path = os.path.join(target_dir, "network_activity.log")
    net_logs = read_text(net_path, "No network activity logged.")
    network_summary = summarise_network_log(net_logs)

    trace_path = os.path.join(target_dir, "trace.log")
    trace_logs = read_text(trace_path, "")
    trace = parse_trace(trace_logs)

    return {
        "report": active_report,
        "diffs": diffs,
        "net_logs": net_logs,
        "network_summary": network_summary,
        "trace_logs": trace_logs,
        "trace": trace,
    }



# ============================================================
# Routes
# ============================================================

@app.route("/")
def index():
    reports = get_all_reports()
    if not reports:
        return render_template(
            "report.html",
            reports=[],
            active_report=None,
            diffs=[],
            net_logs="",
            network_summary={"line_count": 0, "connections": 0},
            trace_logs="",
            trace={"processes": [], "events": [], "process_count": 0, "event_count": 0, "roots": []},
        )
    folder_name = reports[0]["folder_name"]
    data = load_report(folder_name)
    return render_template("report.html", reports=reports, active_report=None, **data)


@app.route("/report/<folder_name>")
def view_report(folder_name):
    reports = get_all_reports()
    if not any(report.get("folder_name") == folder_name for report in reports):
        abort(404)
    data = load_report(folder_name)
    return render_template("report.html", reports=reports, active_report=data, **data)


@app.route("/upload", methods=["POST"])
def upload_sample():
    if "file" not in request.files:
        abort(400, "No file part")
    file = request.files["file"]
    if file.filename == "":
        abort(400, "No selected file")

    filename = secure_filename(file.filename)
    with tempfile.NamedTemporaryFile(delete=False, suffix="_" + filename) as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name
    try:
        metadata, folder_name = detonate.run_analysis(tmp_path)
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        abort(500, f"Analysis failed: {str(e)}")

    if os.path.exists(tmp_path):
        os.unlink(tmp_path)

    return redirect(url_for("view_report", folder_name=folder_name))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)