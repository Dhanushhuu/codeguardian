
import requests
import json
import time
from pathlib import Path

BASE_URL = "http://localhost:8000"

code = Path("data/samples/vulnerable_example.py").read_text(encoding="utf-8")

payload = {
    "files": [
        {
            "filename":  "app.py",
            "language":  "python",
            "content":   code,
            "patch":     "",
            "additions": 80,
            "deletions": 0,
        }
    ]
}

print("Submitting review...")
resp = requests.post(f"{BASE_URL}/review", json=payload, timeout=10)
resp.raise_for_status()
data      = resp.json()
review_id = data["review_id"]
print(f"Review ID : {review_id}")
print(f"Status    : {data['status']}")
print()

seen_events = 0

while True:
    try:
        status_resp = requests.get(f"{BASE_URL}/status/{review_id}", timeout=10)
        status_data = status_resp.json()
    except Exception as e:
        print(f"Poll error: {e}")
        time.sleep(3)
        continue

    status = status_data.get("status", "unknown")
    events = status_data.get("events", [])

    for event in events[seen_events:]:
        print(f"  [{event.get('agent','?'):15s}] {event.get('message','')}")
        seen_events += 1

    if status not in ("queued", "running"):
        print(f"\nFinal status: {status}")
        break

    print(f"  ... {status} (waiting 3s)")
    time.sleep(3)

if status == "complete":

    # Always save full debug state first
    full_status = requests.get(f"{BASE_URL}/status/{review_id}", timeout=10).json()
    with open("debug_state.json", "w", encoding="utf-8") as f:
        json.dump(full_status, f, indent=2, default=str)

    print("\nDEBUG info:")
    print(f"  status keys : {list(full_status.keys())}")
    print(f"  error       : {full_status.get('error')}")
    state = full_status.get("state", {}) or {}
    print(f"  state keys  : {list(state.keys())}")
    print(f"  report type : {type(state.get('report'))}")
    print(f"  report value: {str(state.get('report'))[:200]}")
    print(f"  sec issues  : {len(state.get('security_issues', []))}")
    print(f"  qual issues : {len(state.get('quality_issues', []))}")
    print(f"  fixes       : {len(state.get('fixes', []))}")
    print(f"  tests       : {len(state.get('tests', []))}")
    print()

    # Try /results
    result_resp = requests.get(f"{BASE_URL}/results/{review_id}", timeout=10)
    print(f"  /results HTTP {result_resp.status_code}")
    print(f"  /results body: {result_resp.text[:300]}")
    print()

    report = None
    if result_resp.status_code == 200:
        body = result_resp.json()
        if isinstance(body, dict) and body:
            report = body

    if report:
        print("=" * 60)
        print("  CODEGUARDIAN REPORT")
        print("=" * 60)
        print(f"  Verdict  : {report.get('verdict','N/A').upper()}")
        print(f"  Summary  : {report.get('summary','N/A')}")
        print()

        bd = report.get("severity_breakdown", {})
        print("  Severity Breakdown:")
        print(f"    Critical : {bd.get('critical', 0)}")
        print(f"    High     : {bd.get('high', 0)}")
        print(f"    Medium   : {bd.get('medium', 0)}")
        print(f"    Low      : {bd.get('low', 0)}")
        print()

        sec  = [i for i in report.get("security_issues", []) if not i.get("false_positive")]
        fps  = [i for i in report.get("security_issues", []) if i.get("false_positive")]
        print(f"  Security Issues : {len(sec)} real, {len(fps)} false positives dismissed")
        print(f"  Quality Issues  : {len(report.get('quality_issues', []))}")
        print(f"  Fixes Generated : {len(report.get('fixes', []))}")
        print(f"  Tests Generated : {len(report.get('tests', []))}")
        print()

        if sec:
            print("  Issues Found:")
            for issue in sec:
                print(f"    [{issue['severity'].upper():8s}] {issue['category']} "
                      f"(line {issue['line']}) [{issue['source']}]")
            print()

        if report.get("fixes"):
            print("  Fixes:")
            for fix in report["fixes"]:
                v = "validated" if fix.get("validated") else "needs review"
                print(f"    - {fix['description']} ({v})")
            print()

        if report.get("tests"):
            print("  Tests:")
            for test in report["tests"]:
                print(f"    - {test['filename']} ({test['framework']})")
            print()

        if report.get("pdf_path"):
            print(f"  PDF: {report['pdf_path']}")

        with open("review_result.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print("  Saved to review_result.json")

    else:
        print("Report is empty. Full debug state saved to debug_state.json")
        print("Please check the server terminal for any error traceback.")

elif status == "failed":
    s = requests.get(f"{BASE_URL}/status/{review_id}", timeout=10).json()
    print(f"\nFAILED: {s.get('error', 'unknown error')}")
    print("Check server terminal for full traceback.")