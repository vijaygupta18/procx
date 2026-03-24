#!/usr/bin/env python3
"""ProcX - Process Monitor. Run and open http://localhost:9876"""

import subprocess
import json
import signal
import os
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
from collections import defaultdict


SYSTEM_PROCS = {
    "WindowServer", "launchd", "logd", "opendirectoryd", "trustd",
    "notifyd", "distnoted", "cfprefsd", "bluetoothd", "airportd",
    "locationd", "symptomsd", "searchpartyd", "coreaudiod",
    "mds_stores", "corespotlightd", "WindowManager", "Dock",
    "Finder", "SystemUIServer", "ControlCenter", "rapportd",
    "loginwindow", "UserEventAgent", "CommCenter", "powerd",
    "sharingd", "syslogd", "configd", "iconservicesagent",
    "coreservicesd", "containermanagerd", "usermanagerd",
    "contextstored", "lsd", "diagnosticd", "thermalmonitord",
    "kernelmanagerd", "mediaremoted", "runningboardd",
    "accessibilityauditd", "corebrightnessd", "MTLAssetUpgraderD",
    "backgroundtaskmanagementd", "endpointsecurityd", "swcd",
    "watchdogd", "dasd", "backboardd", "suggestd", "IMDPersistenceAgent",
    "mediaanalysisd", "photolibraryd", "mDNSResponder",
    "securityd", "sandboxd", "secd", "remoted", "timed",
    "triald", "corespeechd", "audioclocksyncd", "appleh13camerad",
    "DockHelper", "helpd", "pidinfo", "maild", "AppleSpell",
    "mdworker_shared", "BackgroundTaskManagementAgent",
    "MENotificationAgent", "spotlightknowledged", "filecoordinationd",
    "SubmitDiagInfo", "mds", "mdworker", "nsurlsessiond",
    "bird", "cloudd", "cloudpaird", "CalendarAgent", "AddressBookSourceSync",
}

# Grouping rules: map process name patterns to group names
GROUP_RULES = [
    (r"Cursor Helper.*", "Cursor"),
    (r"Cursor$", "Cursor"),
    (r"Code Helper.*", "VS Code"),
    (r"^Code$", "VS Code"),
    (r"Comet Helper.*", "Comet"),
    (r"^Comet$", "Comet"),
    (r"^idea$", "IntelliJ IDEA"),
    (r"^claude$", "Claude Code"),
]


def get_group_name(proc_name):
    for pattern, group in GROUP_RULES:
        if re.search(pattern, proc_name):
            return group
    return None


def get_system_stats():
    """Get system-wide CPU and memory stats."""
    # Total physical memory
    result = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True)
    total_mem_bytes = int(result.stdout.strip())
    total_mem_gb = total_mem_bytes / (1024**3)

    # VM stats for memory pressure
    vm = subprocess.run(["vm_stat"], capture_output=True, text=True)
    pages = {}
    for line in vm.stdout.strip().split("\n")[1:]:
        m = re.match(r"(.+?):\s+(\d+)", line)
        if m:
            pages[m.group(1).strip()] = int(m.group(2))

    page_size = 16384  # Apple Silicon default
    used_pages = pages.get("Pages active", 0) + pages.get("Pages wired down", 0)
    used_mem_gb = (used_pages * page_size) / (1024**3)

    # CPU usage via top
    top = subprocess.run(["top", "-l", "1", "-n", "0", "-s", "0"], capture_output=True, text=True)
    cpu_user = cpu_sys = 0
    for line in top.stdout.split("\n"):
        if "CPU usage" in line:
            m = re.findall(r"([\d.]+)%", line)
            if len(m) >= 2:
                cpu_user = float(m[0])
                cpu_sys = float(m[1])
            break

    return {
        "total_mem_gb": round(total_mem_gb, 1),
        "used_mem_gb": round(used_mem_gb, 1),
        "mem_pct": round((used_mem_gb / total_mem_gb) * 100, 1),
        "cpu_user": round(cpu_user, 1),
        "cpu_sys": round(cpu_sys, 1),
        "cpu_total": round(cpu_user + cpu_sys, 1),
    }


def get_processes():
    """Get all user processes with CPU, memory, ports info."""
    result = subprocess.run(
        ["ps", "-eo", "pid,ppid,pcpu,pmem,rss,etime,comm", "-r"],
        capture_output=True, text=True
    )
    port_result = subprocess.run(
        ["lsof", "-i", "-P", "-n"],
        capture_output=True, text=True
    )

    port_map = {}
    for line in port_result.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 9 and "LISTEN" in line:
            pid = parts[1]
            name = parts[-1] if parts[-1] != "(LISTEN)" else parts[-2]
            port = name.split(":")[-1] if ":" in name else ""
            if pid not in port_map:
                port_map[pid] = []
            if port and port not in port_map[pid]:
                port_map[pid].append(port)

    processes = []
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid, ppid, cpu, mem, rss, etime, comm = parts
        pid_int = int(pid)
        if pid_int <= 1:
            continue

        # Simplify name
        name = comm.split("/")[-1] if "/" in comm else comm
        for suffix in [".app/Contents/MacOS/", ".xpc/Contents/MacOS/"]:
            if suffix in comm:
                name = comm.split(suffix)[-1]
                break

        rss_mb = round(int(rss) / 1024, 1)
        cpu_val = float(cpu)
        mem_val = float(mem)
        ports = port_map.get(pid, [])

        # Categorize
        category = "other"
        if any(s in name for s in SYSTEM_PROCS):
            category = "system"
        elif cpu_val < 0.1 and rss_mb < 20:
            category = "system"
        elif any(s in comm for s in ["/Applications/", "/usr/local/", "/opt/homebrew/"]):
            category = "app"
        elif "claude" in comm.lower() or "node" in comm.lower() or "python" in comm.lower():
            category = "app"

        idle = cpu_val < 0.2 and rss_mb > 50 and category == "app"
        group = get_group_name(name)

        processes.append({
            "pid": pid_int,
            "ppid": int(ppid),
            "name": name,
            "command": comm,
            "cpu": cpu_val,
            "mem": mem_val,
            "rss_mb": rss_mb,
            "elapsed": etime.strip(),
            "ports": ports,
            "category": category,
            "idle": idle,
            "group": group,
        })

    return processes


def build_response():
    """Build full API response with processes, groups, stats, and recommendations."""
    procs = get_processes()
    stats = get_system_stats()

    # Build groups
    groups = defaultdict(lambda: {
        "name": "", "pids": [], "cpu": 0, "rss_mb": 0,
        "mem": 0, "ports": [], "count": 0, "idle": True,
    })
    ungrouped = []

    for p in procs:
        if p["group"] and p["category"] == "app":
            g = groups[p["group"]]
            g["name"] = p["group"]
            g["pids"].append(p["pid"])
            g["cpu"] += p["cpu"]
            g["rss_mb"] += p["rss_mb"]
            g["mem"] += p["mem"]
            g["ports"].extend(p["ports"])
            g["count"] += 1
            if p["cpu"] >= 0.2:
                g["idle"] = False
        else:
            ungrouped.append(p)

    group_list = []
    for name, g in groups.items():
        g["ports"] = list(set(g["ports"]))
        g["cpu"] = round(g["cpu"], 1)
        g["rss_mb"] = round(g["rss_mb"], 1)
        g["mem"] = round(g["mem"], 1)
        group_list.append(g)

    # Build recommendations
    recommendations = []
    idle_apps = [p for p in procs if p["idle"] and not p["group"]]
    idle_groups = [g for g in group_list if g["idle"] and g["rss_mb"] > 50]

    total_saveable = sum(p["rss_mb"] for p in idle_apps) + sum(g["rss_mb"] for g in idle_groups)

    if total_saveable > 100:
        items = []
        for g in sorted(idle_groups, key=lambda x: -x["rss_mb"]):
            items.append({"name": g["name"], "rss_mb": g["rss_mb"], "pids": g["pids"], "type": "group"})
        for p in sorted(idle_apps, key=lambda x: -x["rss_mb"]):
            items.append({"name": p["name"], "rss_mb": p["rss_mb"], "pids": [p["pid"]], "type": "process"})
        recommendations.append({
            "type": "free_memory",
            "title": f"Free {total_saveable/1024:.1f} GB" if total_saveable >= 1024 else f"Free {total_saveable:.0f} MB",
            "desc": f"{len(items)} idle processes using memory",
            "items": items[:8],
            "total_mb": round(total_saveable, 1),
        })

    # CPU hogs
    hogs = [p for p in procs if p["cpu"] >= 50 and p["category"] == "app"]
    hog_groups = [g for g in group_list if g["cpu"] >= 50]
    if hogs or hog_groups:
        items = []
        for g in hog_groups:
            items.append({"name": g["name"], "cpu": g["cpu"], "pids": g["pids"], "type": "group"})
        for p in hogs:
            if not p["group"]:
                items.append({"name": p["name"], "cpu": p["cpu"], "pids": [p["pid"]], "type": "process"})
        if items:
            recommendations.append({
                "type": "cpu_hog",
                "title": "High CPU Usage",
                "desc": f"{len(items)} processes using excessive CPU",
                "items": items,
            })

    # Long-running processes
    long_running = []
    for p in procs:
        if p["category"] == "app" and "-" in p["elapsed"]:
            days = int(p["elapsed"].split("-")[0])
            if days >= 2 and p["idle"]:
                long_running.append({"name": p["name"], "days": days, "pids": [p["pid"]], "rss_mb": p["rss_mb"]})
    if long_running:
        recommendations.append({
            "type": "stale",
            "title": "Stale Processes",
            "desc": f"{len(long_running)} processes running for days while idle",
            "items": long_running,
        })

    return {
        "processes": procs,
        "groups": group_list,
        "stats": stats,
        "recommendations": recommendations,
    }


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/data":
            data = build_response()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif parsed.path == "/api/processes":
            procs = get_processes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(procs).encode())
        elif parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), "rb") as f:
                self.wfile.write(f.read())
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/kill":
            content_length = int(self.headers["Content-Length"])
            body = json.loads(self.rfile.read(content_length))
            pids = body.get("pids", [body["pid"]] if "pid" in body else [])
            sig = body.get("signal", "TERM")
            results = []
            for pid in pids:
                pid = int(pid)
                if pid <= 1:
                    results.append({"pid": pid, "error": "Cannot kill system process"})
                    continue
                try:
                    sig_num = signal.SIGTERM if sig == "TERM" else signal.SIGKILL
                    os.kill(pid, sig_num)
                    results.append({"pid": pid, "ok": True})
                except ProcessLookupError:
                    results.append({"pid": pid, "error": "Not found"})
                except PermissionError:
                    results.append({"pid": pid, "error": "Permission denied"})

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"results": results}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = 9876
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.socket.setsockopt(__import__("socket").SOL_SOCKET, __import__("socket").SO_REUSEADDR, 1)
    print(f"\033[1;36mProcX\033[0m running at \033[1;4mhttp://localhost:{port}\033[0m")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()
