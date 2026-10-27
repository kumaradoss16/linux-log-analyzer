from __future__ import annotations
import json   # Convert the report dictionary into JSON-formatted text.

_BAR_WIDTH = 30

# Converts a numerical value into a bar made from # characters.
def _bar(value: int, peak: int) -> str:
    return "#" * round(_BAR_WIDTH * value / peak) if peak else ""



# Formatting report tables
def _table(title: str, rows: list[list]) -> list[str]:
    out = [f"\n{title}", "-" * len(title)]
    if not rows:
        return out + ["   (none)"]
    width = max(len(str(k)) for k , _ in rows)
    return out + [f"   {str(k):<{width}}   {v}" for k, v in rows]


# Convert the analyzer's Python dictionary into a JSON-formatted string.
def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


# Building the main report
def render_text(data: dict) -> str:
    # Tuple unpacking
    s, lg, er, td, al = (
        data["summary"], data["logins"], data["errors"], data["time_distribution"], data["alerts"],
    )

    # Create the report header
    out = ["=" * 60, "LINUX LOG ANALYZER REPORT", "=" * 60, f"Lines read: {s['lines_read'] or 'none'}",
           f"Time range: {s['first_event']} -> {s['last_event']}"]

    # Display login statistics
    out += ["\nLOGINS", "------",
            f"   Failed:    : {lg['failed']}",
            f"   Successful : {lg['successful']}"]
    out += _table("Failed login by source IP", lg["failed_by_ip"])
    out += _table("Failed logins by user", lg["failed_by_user"])
    out += _table("Successful logins by user", lg["successful_by_user"])
    out += _table("Top source IPs (auth + web)", data["top_source_ips"])
    out += _table("Top users (auth)", data["top_users"])

    # Display errors statistics
    out += ["\nERRORS", "------",
            f"   Total {er['total']}   |   system {er['system']}   |   "
            f"web 4xx {er['web_4xx']}   |   web 5xx {er['web_5xx']}"]
    out += _table("System errors by process", er["system_by_process"])
    out += _table("web errors (status path)", er["web_by_status_path"])

    # Display hourly event distributions
    out += ["\n TIME DISTRIBUTION (per hour of day)", "------------------------------"]

    for metric, buckets in td["hourly"].items():
        peak = max(buckets)
        out.append(f"\n  {metric} (peak {peak})")
        for hour, n in enumerate(buckets):
            if n:
                out.append(f"    {hour:02d}:00 {n:>6}  {_bar(n, peak)}")

    # Display security alerts
    out += ["\nALERTS", "------"]
    if al["brute_force_ips"]:
        out.append(f"   Possible brute force (>= {al['threshold']} failures):")
        out += [f"   {ip:<40} {n} failures" for ip, n in al["brute_force_ips"]]
    else:
        out.append("   No brute-force sources above threshold.")
    if al["possible_compromise_ips"]:
        out.append("   !! IPs with any many failures AND a successful login (investigate):")
        out += [f"   {ip}" for ip in al["possible_compromise_ips"]]


