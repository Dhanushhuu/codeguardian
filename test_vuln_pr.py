import pickle
import subprocess

def load_user_data(data):
    return pickle.loads(data)

def get_user(username):
    query = "SELECT * FROM users WHERE name = " + username

def run_command(cmd):
    subprocess.call(cmd, shell=True)
