"""Authenticated Key Exchange (AKE) based on our rrFE
"""

import socket
from hashlib import sha256, sha384
import numpy as np
from socket_helper import send, receive, create_socket, close_socket
import apuf_simulation as apuf
import fuzzy_extractor as fe

APUF_LAYERS = 128 + 1
LOCKER_DIGEST = sha384
TAG_DIGEST = sha256

class User:
    '''User's side of the AKE protocol
    '''
    def __init__(self, L: int, ell: int, lbd: int, uid: bytes): # pylint: disable=invalid-name
        self.L = L  # pylint: disable=invalid-name
        self.ell = ell
        self.lbd = lbd
        self.uid = uid

        self.lockerdigest = LOCKER_DIGEST
        self.tagdigest = TAG_DIGEST

        self.ctxtlen = self.lockerdigest.digest_size
        self.taglen = self.tagdigest.digest_size

        # Simulate the user's APUF
        self.device = apuf.generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)

        # Placeholder for challenges
        self.challenges = None


    def registration(self, server: socket.socket) -> int:
        ''' Registration phase of the AKE, performed by the user
        This is a demo registration with a pre-generated list of challenges.
        A real implementation would use a seed to generate a list of challenges.
        '''

        # Step 1: Generate (DEMO - load) challenges
        self.challenges = np.load("challenges/1_mil_challenges.npy")

        # Step 2: Measure sample W
        sample = bytes(apuf.get_noisy_responses(1, [self.device], self.challenges, 0, 0.05*0.1))

        # Step 3: Send W to the server
        sent = send(server, sample)
        if sent != len(sample):
            print(f"User: Registration - sent {sent} bytes instead of {len(sample)}")
            return None

        return sent
        # print(f"User: Sent the sample ({sent} bytes)")


    def ake(self, server: socket.socket):
        '''TODO
        '''

        # Step 1: Initiate the protocol
        # (skip sending hello, just send the uid)
        sent = send(server, self.uid)
        if sent != len(self.uid):
            print(f"User: AKE step 1 - sent {sent} bytes instead of {len(self.uid)}")
            return None

        # Step 2: Wait to receive a P_sid, nonce1, and server's id
        ctxt_size = self.L * self.ctxtlen
        payload_size = ctxt_size + self.taglen
        # First, receive all those ciphertexts and tag. Parse appropriately (TODO may need to pad)
        received = receive(server, payload_size)
        if len(received) != payload_size:
            print(f"User: AKE - expected {payload_size} bytes, received {len(received)}")
            return None

        # Parse the payload
        ctxt = received[:ctxt_size]
        tag = received[ctxt_size:]

        # Split the ciphertexts
        # TODO list comprehension?

        # Then, recveive nonce (length = lbd) and uid (length = 1)
        # payload_size = self.lbd + len(self.uid)
        # TODO


        return None


class Server:
    '''Server side of the AKE protocol
    '''
    def __init__(self, L: int, ell: int, lbd: int, uid: bytes): # pylint: disable=invalid-name
        self.L = L  # pylint: disable=invalid-name
        self.ell = ell
        self.lbd = lbd
        self.uid = uid

        # Placeholder for the sample
        self.sample = bytes(L)


    def server_registration(self, user: socket.socket) -> bytes:
        '''Registration phase of the AKE, performed by the server
        '''

        # Step 1: Receive the sample (W)
        self.sample = receive(user, self.L)
        if len(self.sample) != self.L:
            print(f"Server: Registration - received {len(self.sample)} bytes instead of {self.L}")
            return None

        # TODO what should I return?
        return None
