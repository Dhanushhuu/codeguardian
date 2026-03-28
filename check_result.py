import requests
import json
import time

review_id = "3025d966-f458-4a3d-b41d-b2b2fddd5d0a"  # your ID from send_review.py

print(f"Checking review: {review_id}\n")

# Poll until complete
while True:
    status_resp = requests.get(f"http://localhost:8000/status/{review_id}")
    status_data = status_resp.json()
    status = status_data.get("status")
    print(f"Status: {status}")

    # Print any new events
    for event in status_data.get("events", []):
        print(f"  [{event['agent']}] {event['message']}")

    if status == "complete":
        print("\n--- FULL RESULTS ---")
        result_resp = requests.get(f"http://localhost:8000/results/{review_id}")
        print(json.dumps(result_resp.json(), indent=2))
        break
    elif status == "failed":
        print("Review failed:", status_data.get("error"))
        break

    time.sleep(3)