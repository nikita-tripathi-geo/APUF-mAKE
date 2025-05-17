#!/usr/bin/python3
"""Client-side implementation of the mAKE protocol.

This module implements the user-facing operations for the
mAKE (mutually Authenticated Key Exchange) protocol.
It includes two methods: registration and the actual AKE.

This code is for demonstrational purposes only,
it is not suitable for a production environment.
"""
from secrets import token_bytes
from hashlib import sha256
import socket
from numpy import load as npload

from socket_helper import (
    create_socket,
    close_socket,
    send_msg,
    recv_msg,
    SocketIOError,
)
from apuf import APUF
from fuzzy_extractor import FuzzyExtractor


def user_registration(server: socket.socket, puf: APUF) -> None:
    """User-side registration phase of mAKE.

    This demo loads a pre-generated list of PUF challenges, measures the
    corresponding PUF responses, and sends the sample to the server.

    Args:
        server (socket.socket): Connected socket to the server.
        puf (APUF): PUF device used to generate responses.

    Raises:
        SocketIOError: If sending the registration sample fails.
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


def user_ake(server: socket.socket, usr_id: bytes, puf: APUF) -> bytes:
    """User-side protocol execution phase of mAKE.

    This function executes the following steps:
    1. Send 'hello' and user id (A) to server.
    2. Receive public helper data, nonce1, and server id (B).
    3. Remeasure PUF responses and obtain a fresh sample (W').
    4. Use fuzzy extractor to recover shared secret K_sid.
    5. Compute authentication hash h1', generate nonce2, and send both.
    6. Receive and verify server hash h2.
    7. Derive session key.

    Args:
        server (socket.socket): Connected socket to the server.
        usr_id (bytes): User identifier (4-byte value).
        puf (APUF): Initialized PUF instance used to generate responses.

    Returns:
        bytes: The established session key, or empty bytes on failure.

    Raises:
        SocketIOError: On any socket communication error or protocol mismatch.
    """

    # Step 1: Send a hello and usr_id (4 + 4 = 8 bytes)
    try:
        send_msg(server, b"helo" + usr_id)
    except SocketIOError as e:
        print(f"(User) AKE failed on message 1: {e}")
        return b""

    # Step 2: Remeasure W'
    challenges = npload("challenges/1_mil_challenges.npy")
    new_sample = bytes(puf.get_responses(challenges, nmean=0.0, nstd=0.005))

    # Step 3: Receive public helper, n1 (nonce1), srv_id (B) *AND* FE nonces
    try:
        data = recv_msg(server)
        if len(data) != 224044:
            # TODO Need a new error type? I can make an abstract "entity" class
            # with register and ake methods + new ProtocolException(Exception)
            raise SocketIOError(
                f"Expected 224044 bytes (P_sid + nonce1 + B), got {len(data)}"
            )
    except SocketIOError as e:
        print(f"(User) AKE failed on message 2: {e}")
        return b""

    # Parse data [(p_1, ..., p_\ell), seed, T, nonce1, B]
    joint_ctxt = data[:168000]
    seed = data[168000:168004]
    tag = data[168004:168036]
    n1 = data[168036:168040]
    srv_id = data[168040:168044]
    nonces = data[168044:]

    fe_seed = int.from_bytes(seed, "big")

    # Step 4: Recover K_sid
    fe = FuzzyExtractor(
        sample_len=192,
        locker_num=3500,
        key_len=128,
        mac_key_len=128,
        padding_len=128,
        nonce_len=128,
        seed=fe_seed,
    )
    fe.joint_ctxt = joint_ctxt
    fe.tag = tag

    # Deserialize (split) joint_ctxt and nonces
    fe.ctxt = [joint_ctxt[i : i + 48] for i in range(0, 3500 * 48, 48)]
    fe.h = [nonces[i : i + 16] for i in range(0, 3500 * 16, 16)]

    # K_sid
    key = fe.reproduce(new_sample)

    if key is None:
        print("(User) AKE failed due to FE: Could not recover key")
        return b""

    # Step 5: Compute hashes
    todigest = joint_ctxt + seed + tag + usr_id + srv_id + key
    h1_prime = sha256(n1 + todigest).digest()
    n2 = token_bytes(4)
    h2_prime = sha256(n2 + todigest).digest()

    # print(n1)
    # print(todigest)

    # Step 6: Send h1', n2
    try:
        send_msg(server, h1_prime + n2)
    except SocketIOError as e:
        print(f"(User) AKE failed on message 3: {e}")
        return b""

    # Step 7: Receive h2
    try:
        h2 = recv_msg(server)
        if len(h2) != 32:
            raise SocketIOError(f"Expected 32 bytes (h2'), got {len(h2)}")
        if h2 != h2_prime:
            raise SocketIOError(
                f"Expected same h2 and h2'. h2: {h2}, h2': {h2_prime}"
            )
    except SocketIOError as e:
        print(f"(User) AKE failed on message 4: {e}")
        return b""

    # Step 8: Generate session key
    session_key = sha256(todigest).digest()

    return session_key


if __name__ == "__main__":
    from sys import argv

    # assume input is correct
    print(f"IP: {argv[1]}, PORT: {argv[2]}")
    ip = argv[1]
    port = int(argv[2])

    # Create a socket
    srv = create_socket(ip, port)

    # Initialize a PUF instance
    usr_puf = APUF(128)

    # Registration
    user_registration(srv, usr_puf)

    # AKE
    skey = user_ake(srv, b"user", usr_puf)
    print(f"Session key: {skey}")

    # Cleanup
    close_socket(srv)

    print("Done!")
