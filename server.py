#!/usr/bin/python3
"""Server-side implementation of the mAKE protocol.

This module implements the server-facing operations for the
mAKE (mutually Authenticated Key Exchange) protocol.
It includes two methods: registration and the actual AKE.

This code is for demonstrational purposes only,
it is not suitable for a production environment.
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


def server_registration(user: socket.socket, resp_filename: str) -> None:
    """Server-side registration phase of mAKE.

    This function receives the user's responses (W) and stores them in a file.

    Args:
        user (socket.socket): Connected socket from the user.
        resp_filename (str): Path to the file where the sample will be stored.

    Raises:
        SocketIOError: If receiving the sample (W) fails.
    """
    # Step 1: Receive the sample (W)
    try:
        sample = recv_msg(user)
        with open(resp_filename, "wb") as f:
            f.write(sample)
    except SocketIOError as e:
        print(f"(Server) Registration failed: {e}")

    return


def server_ake(
    user: socket.socket, srv_id: bytes, w_filename: str, fe_seed: int
) -> bytes:
    """Server-side protocol execution phase of mAKE.

    This function executes the following steps:
      1. Receive 'hello' and user id (A) from client.
      2. Load PUF response and use fuzzy extractor to get K and helper data.
      3. Generate nonce1 and first authentication hash h1.
      4. Send helper data, nonce1, and server id (B) to user.
      5. Receive and verify client's authentication hash h1'. Receive nonce2.
      6. Compute and send second authentication hash h2'.
      7. Derive and return session key.

    Args:
        user (socket.socket): Connected socket from the user.
        srv_id (bytes): Server identifier (4-byte value).
        w_filename (str): File path to stored PUF sample from registration.
        fe_seed (int): Seed used to initialize the fuzzy extractor.

    Returns:
        bytes: The established session key, or empty bytes on failure.

    Raises:
        SocketIOError: On any socket communication error or protocol mismatch.
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
