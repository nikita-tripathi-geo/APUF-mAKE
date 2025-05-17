#!/usr/bin/python3
"""Implements the server-side of the mAKE protocol.

TODO
"""
from secrets import token_bytes
from hashlib import sha256
import socket

from socket_helper import (
    create_socket,
    close_socket,
    send_msg,
    recv_msg,
    SocketIOError,
)
from fuzzy_extractor import FuzzyExtractor


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


def server_ake(
    user: socket.socket, srv_id: bytes, w_filename: str, fe_seed: int
) -> bytes:
    """TODO
    fe_seed is the seed used by FE :D
    """

    # Step 1: Receives hello and A (4 + 4 = 8 bytes)
    try:
        data = recv_msg(user)
        if len(data) != 8:
            # TODO Need a new error type? I can make an abstract "entity" class
            # with register and ake methods + new ProtocolException(Exception)
            raise SocketIOError(f"Expected 8 bytes (hello+A), got {len(data)}")
    except SocketIOError as e:
        print(f"(Server) AKE failed on message 1: {e}")
        return b""

    # We call A usr_id for readability
    usr_id = data[4:]

    # Step 1.1: Reads W and runs FE.Gen(W)
    with open(w_filename, "rb") as f:
        stored_sample = f.read()

    fe = FuzzyExtractor(
        sample_len=192,
        locker_num=3500,
        key_len=128,
        mac_key_len=128,
        padding_len=128,
        nonce_len=128,
        seed=fe_seed,
    )

    # K_sid
    key = fe.generate(stored_sample)
    # P_sid
    ctxt = fe.joint_ctxt
    # T
    tag = fe.tag

    # Byte object with all the ctxts, seed, and tag (public output of FE.Gen)
    public_helper = ctxt + fe_seed.to_bytes(4, "big") + tag

    # Step 1.2: Generates a nonce and finds h1
    n1 = token_bytes(4)
    todigest = public_helper + usr_id + srv_id + key
    h1 = sha256(n1 + todigest).digest()

    # Step 2: Send ctxt, n1, srv_id (B), FE nonces to the user
    try:
        send_msg(user, public_helper + n1 + srv_id + b"".join(fe.h))
    except SocketIOError as e:
        print(f"(Server) AKE failed on message 2: {e}")
        return b""

    # Step 3: Receive h1' and n2 (nonce2), which is 32+4 = 36 bytes
    try:
        data = recv_msg(user)
        if len(data) != 36:
            raise SocketIOError(
                f"Expected 36 bytes (h1'+nonce2), got {len(data)}"
            )
        h1_prime, n2 = data[:32], data[32:]

        if h1_prime != h1:
            raise SocketIOError(
                f"Expected same h1 and h1'. h1: {h1}, h1': {h1_prime}"
            )
    except SocketIOError as e:
        print(f"(Server) AKE failed on message 3: {e}")
        return b""

    # Step 3.1: generate second hash using nonce2
    h2_prime = sha256(n2 + todigest).digest()

    # Step 4: Send ctxt, n1, srv_id (B) to the user
    try:
        send_msg(user, h2_prime)
    except SocketIOError as e:
        print(f"(Server) AKE failed on message 4: {e}")
        return b""

    # Step 5: Generate session key
    session_key = sha256(todigest).digest()

    return session_key


if __name__ == "__main__":
    from sys import argv

    # assume input is correct
    print(f"IP: {argv[1]}, PORT: {argv[2]}")
    ip = argv[1]
    port = int(argv[2])

    # setup
    filename = "registered_W.bin"

    # Create a socket
    srv = create_socket(ip, port, listen=True)

    # Accept a connection from the client
    cli, addr = srv.accept()

    # Registration
    server_registration(cli, filename)

    # AKE
    skey = server_ake(cli, b"srvr", filename, 3)
    print(f"Session key: {skey}")

    # Cleanup
    close_socket(srv)

    print("Done!")
