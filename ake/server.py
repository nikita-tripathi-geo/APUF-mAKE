#!/usr/bin/python3
"""Implements the server-side of the mAKE protocol.

TODO
"""
from hashlib import sha256, sha384
import socket

from socket_helper import create_socket, close_socket, send_msg, recv_msg, SocketIOError
# from .. import fuzzy_extractor as fe



def server_registration(user: socket.socket, result_filename: str) -> None:
    """Registration phase of the AKE, performed by the server.
    TODO - google-style docstring
    """
    # Step 1: Receive the sample (W)
    try:
        sample = recv_msg(user)
        with open(result_filename, "wb") as f:
            f.write(sample)
    except SocketIOError as e:
        print(f"(Server) Registration failed: {e}")

    return



if __name__ == "__main__":
    from sys import argv
    # assume input is correct
    print(f"IP: {argv[1]}, PORT: {argv[2]}")
    ip = argv[1]
    port = int(argv[2])

    # Create a socket
    srv = create_socket(ip, port, listen=True)

    # Accept a connection from the client
    cli, addr = srv.accept()

    # Registration
    server_registration(cli, "registered_W.bin")

    # AKE
    # ...

    # Cleanup
    close_socket(srv)

    print("Done!")
