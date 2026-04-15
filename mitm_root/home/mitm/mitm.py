#!/usr/bin/env python3
"""
Network Security - University of Denver

mitm.py

This file holds the MITM code that you can run in the intermediate network node
between the client and server of the simple file storage service. The code currently
just forwards the data back and forth, but you will probably want to modify it for
testing network-based attacks. Review the documentation posted in Canvas for details.

NOTE: You can write other attack scripts as well. 
"""

import socket
import threading
import json
import signal
import sys

BUFFER_SIZE = 4096

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 15000

# Linux transparent proxy socket option
SOL_IP = socket.SOL_IP
IP_TRANSPARENT = 19


def recv_line(conn):
    """
    Reads data until newline in intercepted connection

    :param conn: a network connection object
    """
    
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            return None
        data += chunk
    return data


def make_listener():
    """
    Creates a transparent interceptor socket that captures traffic 
    redirected to it, even if the destination IP isn't local

    :returns: a listener socket 
    """
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(1.0)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen()
    return s


def make_transparent_outbound(src_ip, dst_ip, dst_port):
    """
    Creates an outbound connection that spoofs the source IP (src_ip),
    making this node invisible to the final destination (dst_ip)

    :param src_ip: source IP address to spoof
    :param dst_ip: destination IP address
    :param dst_port: destination port
    :returns: a socket connection (connected) object
    """
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Preserve only the client's IP
    # Let the kernel choose the source port
    s.bind((src_ip, 0))
    s.connect((dst_ip, dst_port))
    return s


def forward_client_to_server(client_conn, server_conn):
    """
    Intercepts a request line from client and forwards it to server

    :param client_conn: a network connection object to the client
    :param server_conn: a network connection object to the server
   
    NOTE: This is where you can observe/manipulate client->server data
    """
   
    try:
        while True:
            line = recv_line(client_conn)
            if line is None:
                break
            
            print(f"[MITM] C->S {line.decode('utf-8', errors='replace').rstrip()}")                       
            server_conn.sendall(line)

    except Exception as e:
        print(f"[MITM] client->server error: {e}")
    finally:
        try:
            server_conn.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def forward_server_to_client(server_conn, client_conn):
    """
    Intercepts a response line from server and forwards it to client

    :param server_conn: a network connection object to the server
    :param client_conn: a network connection object to the client
   
    NOTE: This is where you can observe/manipulate server->client data
    """
   
    try:
        while True:
            line = recv_line(server_conn)
            if line is None:
                break

            print(f"[MITM] S->C {line.decode('utf-8', errors='replace').rstrip()}")
            client_conn.sendall(line)

    except Exception as e:
        print(f"[MITM] server->client error: {e}")
    finally:
        try:
            client_conn.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_conn):
    """
    Handles an intercepted connection

    :param client_conn: a network connection object to the client
    """
    
    server_conn = None
    try:
        # Get client/server IP and ports
        client_ip, client_port = client_conn.getpeername()
        dst_ip, dst_port = client_conn.getsockname()

        print(f"[MITM] intercepted connection {client_ip}:{client_port} -> {dst_ip}:{dst_port}")

        # Create a transparent connection to server
        server_conn = make_transparent_outbound(
            src_ip=client_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )

        # Start a thread to forward client->server data
        t1 = threading.Thread(
            target=forward_client_to_server,
            args=(client_conn, server_conn),
            daemon=True,
        )
        
        # Start a thread to forward server->client data
        t2 = threading.Thread(
            target=forward_server_to_client,
            args=(server_conn, client_conn),
            daemon=True,
        )

        print("[MITM] started forwarding threads")

        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        print(f"[MITM] error intercepting connection: {e}")
    finally:
        try:
            client_conn.close()
        except Exception:
            pass
        if server_conn is not None:
            try:
                server_conn.close()
            except Exception:
                pass


def signal_handler(sig, frame):
    print("\n[MITM] Shutting down")
    sys.exit(0)
    
    
def main():
    """
    Create listener to intercept connections to server; upon connection
    run handle_client to create transparent link to server
    """
    # Register the handler for Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Listen for connections 
    listen_sock = make_listener()
    print(f"[MITM] transparent listener on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        try:
            client_conn, _ = listen_sock.accept()
        except socket.timeout:
            continue  # loop back and try accept() again
        except Exception as e:
            print(f"[MITM] shutting down: {e}")
            break
            
        threading.Thread(target=handle_client, args=(client_conn,), daemon=True).start()


if __name__ == "__main__":
    main()
