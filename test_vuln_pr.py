# Replace the file with actual Python code
cat > test_vuln_pr.py << 'EOF'
import pickle
import subprocess

def load_user_data(data):
    return pickle.loads(data)  # insecure deserialization

def get_user(username):
    query = "SELECT * FROM users WHERE name = " + username  # SQL injection

def run_command(cmd):
    subprocess.call(cmd, shell=True)  # shell injection
