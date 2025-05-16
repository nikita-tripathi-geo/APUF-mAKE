#!/usr/bin/python3
"""Implements the client-side of the mAKE protocol.

TODO
"""
from hashlib import sha256, sha384
import socket
from numpy import load as npload

from socket_helper import create_socket, close_socket, send_msg, recv_msg, SocketIOError
from apuf import APUF
# from .. import fuzzy_extractor as fe



def user_registration(server: socket.socket, puf: APUF) -> None:
    """ Registration phase of the mAKE, performed by the user
    This is a demo registration with a pre-generated list of challenges.
    A real implementation would use a seed to generate a list of challenges.
    TODO google-style docstrings
    """

    # Step 1: Generate challenges (DEMO: we load instead)
    challenges = npload("challenges/1_mil_challenges.npy")

    # Step 2: Measure sample W
    sample = bytes(puf.get_responses(challenges, nmean=0.0, nstd=0.005))

    # Step 3: Send W to the server
    try:
        send_msg(server, sample)
    except SocketIOError as e:
        print(f"(User) Registration failed: {e}")

    return



if __name__ == "__main__":
    from sys import argv
    # assume input is correct
    print(f"IP: {argv[1]}, PORT: {argv[2]}")
    ip = argv[1]
    port = int(argv[2])

    # Create a socket
    srv = create_socket(ip, port)

    # Initialize a PUF instance
    puf = APUF(128)

    # Registration
    user_registration(srv, puf)

    # AKE
    # ...

    # Cleanup
    close_socket(srv)

    print("Done!")
