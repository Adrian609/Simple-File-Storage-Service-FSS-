#!/usr/bin/env python3
"""
Network Security - University of Denver

server.py

This file holds the server code for a simple file storage service. The code is
intentionally not secure for use in an adversarial network setting. You goal 
is to review and rewrite the code to make it secure in such a setting, while
keeping its functionality intact. Review the documentation posted in Canvas for
details.

"""

import json
import os
import signal
import socket
import threading
import uuid
import sys
import hashlib

HOST = "10.0.8.2"                # server namespace IP
PORT = 9001                      # server listening port
STORAGE_DIR = "server_storage"   # folder where files are stored

SESSIONS = {}                    # server tokens dictionary
CLIENT_LIMIT = 512  # DO NOT CHANGE: only enough resources to allow 1024 clients


# Semaphore to enforce max connections
connection_semaphore = threading.Semaphore(CLIENT_LIMIT)


# You may decide to store the user and password data in a different manner, but
# whatever method you use, the account 'mitm' with password 'mitm123' must be
# present. Consider it an account that an attacker created on the system.
try:

    with open("users.json", "r") as file:   # load user names and passwords
        USERS = json.load(file)
        
except Exception as e:
    print(f"[SERVER] error reading user file: {e}")
    sys.exit(1)
    
# Check if storage directory exists
if not os.path.isdir(STORAGE_DIR):
    print("[SERVER] storage directory not found")
    sys.exit(1)



def recv_line(conn):
    """
    Receive data from a network connection until a newline

    :param conn: a network connection object
    :returns: read data (without the ending newline)
    """
    
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
    return data.decode("utf-8").strip()


def send_json(conn, obj):
    """
    Write a dictionary object as JSON to a network connection
    
    :param conn: a network connection object
    :param obj: a dictionary object
    """
    
    conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def require_auth(req):
    """
    Retrieve username associated with a token from SESSIONS global
    
    :param req: a received request
    :returns: username corresponding to token in request
    """
    
    token = req.get("token", "")
    return SESSIONS.get(token)


def add_to_sessions(token, username):
    """
    Add a token and username to SESSIONS global
    
    :param token: a token
    :param username: a username
    :returns: True on suceess, else False
    """
    
    if len(SESSIONS) < CLIENT_LIMIT:
        SESSIONS[token] = username
        return True
    else:
        return False
    

def handle_create(conn, req):
    """
    Handle the CREATE command

    :param conn: a network connection object
    :param req: a received request
    """
    
    username = req.get("username", "").strip()
    password = req.get("password", "").strip()

    if not username or not password:
        send_json(conn, {"status": "error", "message": "missing username or password"})
        return

    if username in USERS:
        send_json(conn, {"status": "error", "message": "user already exists"})
        return

    # Create user directory
    user_dir = f"{STORAGE_DIR}/{username}"
    os.makedirs(user_dir, exist_ok=True)
    
    # Update in-memory users
    USERS[username] = password

    # Write back to users.json
    with open("users.json", "w", encoding="utf-8") as f:
        json.dump(USERS, f, indent=4)

    send_json(conn, {"status": "ok", "message": "account created"})

        
def handle_auth(conn, req):
    """
    Handle the AUTH command
    
    :param conn: a network connection object
    :param req: a received request
    """
    
    username = req.get("username", "")
    password = req.get("password", "")

    # Check password, then generate and respond with token
    if username in USERS and USERS[username] == password:
        token = str(uuid.uuid4())
        if add_to_sessions(token, username) is True:
            send_json(conn, {"status": "ok", "token": token})
        else:
            send_json(conn, {"status": "error", "message": "server overload"})
    else:
        send_json(conn, {"status": "error", "message": "invalid credentials"})


def handle_list(conn, req):
    """
    Handle the LIST command
    
    :param conn: a network connection object
    :param req: a received request
    """
    
    # Check token
    username = require_auth(req)
    if not username:
        send_json(conn, {"status": "error", "message": "unauthorized"})
        return

    user_dir = f"{STORAGE_DIR}/{username}"

    # Read metadata of files in user's directory and form response 
    try:
        files = []
        for filename in os.listdir(user_dir):
            path = os.path.join(user_dir, filename)

            if not os.path.isfile(path):
                continue

            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()

            modified_ts = os.path.getmtime(path)

            files.append({
                "name": filename,
                "modified_ts": modified_ts,
                "digest": digest,
            })

        send_json(conn, {"status": "ok", "files": files})
    except Exception as e:
        send_json(conn, {"status": "error", "message": str(e)})


def handle_upload(conn, req):
    """
    Handle the UPLOAD command
    
    :param conn: a network connection object
    :param req: a received request
    """
    
    # Check token
    username = require_auth(req)
    if not username:
        send_json(conn, {"status": "error", "message": "unauthorized"})
        return

    filename = req.get("filename", "")
    content = req.get("content", "")
    path = os.path.join(f"{STORAGE_DIR}/{username}", filename)

    try:
        # Create a file with the provided contents
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
            
        # Obtain metadata to include in response
        ts = os.path.getmtime(path)
        sha256_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
                
        send_json(conn, {
            "status": "ok",
            "message": f"upload complete for {username}",
            "ts": ts,
            "sha256":sha256_digest,
        })
    except Exception as e:
        send_json(conn, {"status": "error", "message": str(e)})


def handle_download(conn, req):
    """
    Handle the DOWLOAD command
    
    :param conn: a network connection object
    :param req: a received request
    """
    
    # Check token
    username = require_auth(req)
    if not username:
        send_json(conn, {"status": "error", "message": "unauthorized"})
        return

    filename = req.get("filename", "")
    path = os.path.join(f"{STORAGE_DIR}/{username}", filename) 

    try:
        # Read the file contents
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Obtain metadata to include in response
        modified_ts = os.path.getmtime(path)
        sha256_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

        send_json(conn, {
            "status": "ok",
            "filename": filename,
            "content": content,
            "modified_ts": modified_ts,
            "sha256": sha256_digest,
        })
    except Exception as e:
        send_json(conn, {"status": "error", "message": str(e)})


def handle_logout(conn, req):
    """
    Handle the LOGOUT command
    
    :param conn: a network connection object
    :param req: a received request
    """
    
    # Check token
    username = require_auth(req)
    if not username:
        send_json(conn, {"status": "error", "message": "unauthorized"})
        return
    
    # Send response
    send_json(conn, {"status": "ok", "message": f"{username} logged out"})    
        
        
def dispatch(conn, req):
    """
    Retrive command from request and run handler
    
    :param conn: a network connection object
    :param req: a received request
    """
    
    action = req.get("action", "")

    if action == "CREATE":
        handle_create(conn, req)
    elif action == "AUTH":
        handle_auth(conn, req)
    elif action == "LIST":
        handle_list(conn, req)
    elif action == "UPLOAD":
        handle_upload(conn, req)
    elif action == "DOWNLOAD":
        handle_download(conn, req)
    elif action == "LOGOUT":
        handle_logout(conn, req)
    else:
        send_json(conn, {"status": "error", "message": "unknown action"})


def handle_client(conn, addr):
    """
    The command processing loop for a client -- read a request and dispatch
    
    :param conn: a network connection object
    :param addr: the (IP, PORT) tuple of client
    """
    
    print(f"[SERVER] connection from {addr}")
    try:
        while True:
            line = recv_line(conn)  # receive request
            if line is None:
                break

            try:
                req = json.loads(line) # convert request to JSON
            except json.JSONDecodeError:
                send_json(conn, {"status": "error", "message": "invalid json"})
                continue

            print(f"[SERVER] recv: {req}")
            dispatch(conn, req)  # handle the command

    except Exception as e:
        print(f"[SERVER] error with {addr}: {e}")
    finally:
        conn.close()
        print(f"[SERVER] disconnected {addr}")


def signal_handler(sig, frame):
    print("\n[SERVER] Shutting down")
    sys.exit(0)
    



def main():
    """
    Create server to listen for connections. A maximum of CLIENT_LIMIT connections
    are allowed. DO NOT MODIFY the value of CLIENT_LIMIT.
    """
    
    # Register the handler for Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1.0)
        s.bind((HOST, PORT))
        s.listen(128)
        
        print(f"[SERVER] listening on {HOST}:{PORT}")

        while True:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue  # loop back and try accept() again
            except Exception as e:
                print(f"[SERVER] shutting down: {e}")
                break
            
            if connection_semaphore.acquire(blocking=False):
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            else:
                print(f"[SERVER] rejected connection from {addr}")
                send_json(conn, {"status": "error", "message": "server busy, try again later"})
                conn.close
                
                

if __name__ == "__main__":
    main()
