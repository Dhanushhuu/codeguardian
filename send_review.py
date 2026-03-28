import requests
import json

payload = {
    "files": [
        {
            "filename":  "app.py",
            "language":  "python",
            "content":   "import pickle\ndef load(data): return pickle.loads(data)",
            "patch":     "",
            "additions": 2,
            "deletions": 0,
        }
    ]
}

resp = requests.post("http://localhost:8000/review", json=payload)
print(json.dumps(resp.json(), indent=2))