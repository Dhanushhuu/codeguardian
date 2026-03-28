# Create a test file
echo "import pickle

def load_user_data(data):
    return pickle.loads(data)  # insecure deserialization

def get_user(username):
    query = 'SELECT * FROM users WHERE name = ' + username  # SQL injection
