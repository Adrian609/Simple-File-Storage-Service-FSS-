#!/usr/bin/env python3
"""
Network Security - University of Denver

client.py

This file holds the client code for a simple file storage service. The code is
intentionally not secure for use in an adversarial network setting. You goal 
is to review and rewrite the code to make it secure in such a setting, while
keeping its functionality intact. Review the documentation posted in Canvas for
details.

"""

import json
import socket
import getpass

SERVER_HOST = "10.0.8.2"   # server IP
SERVER_PORT = 9001         # server port


def send_recv(sock, obj):
    """
    Send a request to server and retrieve response
    
    :param sock: a network connection object
    :param obj: request as a dictionary object
    :returns: response from server as dictionary object
    """
    
    # Send the request in JSON format
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    # Receive response until newline and return
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("server disconnected")
        data += chunk

    return json.loads(data.decode("utf-8").strip())


def main():
    """
    Obtains user command choice from a menu and processes it
    """
    
    token = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    
        # Connect to server        
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[CLIENT] connected to server at {SERVER_HOST}:{SERVER_PORT}")

        while True:
            # Build the menu
            print("\nChoose:")
            print("1) Login")
            print("2) Create account")
            print("3) List files")
            print("4) Upload file")
            print("5) Download file")
            print("6) Logout")
            print("7) Quit")
            choice = input("> ").strip()

            # Process menu items based on choice
            if choice == "1":
                username = input("Username: ").strip()
                password = getpass.getpass(prompt="Password: ").strip()
                resp = send_recv(sock, {
                    "action": "AUTH",
                    "username": username,
                    "password": password,
                })
                print(resp)
                if resp.get("status") == "ok":
                    token = resp.get("token")

            elif choice == "2":
                username = input("New username: ").strip()
                password = getpass.getpass(prompt="New password: ").strip()
                confirm = getpass.getpass(prompt="Confirm password: ").strip()

                if password != confirm:
                    print("Error: Passwords do not match")
                    continue

                resp = send_recv(sock, {
                    "action": "CREATE",
                    "username": username,
                    "password": password,
                })
                print(resp)

            elif choice == "3":
                resp = send_recv(sock, {
                    "action": "LIST",
                    "token": token,
                })
                print(resp)

            elif choice == "4":
                filename = input("Filename: ").strip()
                print("Enter file content. End with a single line containing EOF")
                lines = []
                while True:
                    line = input()
                    if line == "EOF":
                        break
                    lines.append(line)
                content = "\n".join(lines)

                resp = send_recv(sock, {
                    "action": "UPLOAD",
                    "token": token,
                    "filename": filename,
                    "content": content,
                })
                print(resp)

            elif choice == "5":
                filename = input("Filename: ").strip()
                resp = send_recv(sock, {
                    "action": "DOWNLOAD",
                    "token": token,
                    "filename": filename,
                })
                print(resp)

            elif choice == "6":
                resp = send_recv(sock, {
                    "action": "LOGOUT",
                    "token": token,
                })
                print(resp)
                
            elif choice == "7":
                print("[CLIENT] goodbye")
                break

            else:
                print("Invalid choice")


if __name__ == "__main__":
    main()
