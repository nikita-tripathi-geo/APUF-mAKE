#!/usr/bin/python3
"""Robustly Reusable Fuzzy Extractor for noisy sources, such as APUF responses.

The Fuzzy Extractor ensures robust cryptographic key generation even when the input data is
noisy. It supports multithreaded reproduction attempts to enhance performance with large ell.

Classes:
    FuzzyExtractor: A class for key encoding and recovery using noisy samples.

Functions:
    main(num_rep: int, locker_num: int) -> None:
        Simulates the Fuzzy Extractor workflow using Arbiter PUF-based samples.

Dependencies:
    - numpy: To read pre-generated challenges.
    - apuf_simulation: Simulates Arbiter PUFs and generates noisy responses.
    - utilities.xor_bytes: Utility function for XOR operations.

Example:

    ```python
    from fuzzy_extractor import FuzzyExtractor
    from apuf_simulation import generate_n_APUFs, get_noisy_responses
    import numpy as np

    # Generate Arbiter PUF samples
    apuf = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)
    challenges = np.load("challenges/1_mil_challenges.npy")

    # Initialize Fuzzy Extractor
    fe = FuzzyExtractor()

    # Generate and reproduce a key
    server_sample = bytes(get_noisy_responses(1, [apuf], challenges, 0, 0.05 * 0.1))
    key = fe.generate(server_sample)
    user_sample = bytes(get_noisy_responses(1, [apuf], challenges, 0, 0.05 * 0.1))
    recovered_key = fe.reproduce(user_sample)

    assert key == recovered_key
    ```

Attributes:
    None. This module does not define global-level attributes.

Notes:
    - This implementation assumes Python 3.12.6+
    - Some methods (`reproduce_multithreaded` and `reproduce_process`) are marked as TODO 
      and require further refinement.

"""

# IMPORTS
from secrets import token_bytes
from operator import itemgetter
import multiprocessing
import hmac
from hashlib import sha384, sha256

import logging
import time

import numpy as np
from utilities import xor_bytes
from apuf_simulation import generate_n_APUFs, get_noisy_responses

# Configure logging to output to both console and a file
logging.basicConfig(
    level=logging.DEBUG,  # Change to DEBUG for more detailed logs
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("fuzzy_extractor.log", mode="a"),  # Log file
        # logging.StreamHandler()  # Console output
    ]
)

class FuzzyExtractor:
    '''
    Implements a Fuzzy Extractor for key encoding and recovery using noisy data.
    
    This class allows generation of a cryptographic key using noisy samples,
    and can reproduce the key using a "fresh" samples that close to the original.
    
    Attributes:
        m (int): Length of individual sample in bits.
        ell (int): Number of lockers.
        xi (int): Length of the generated key in bytes.
        lbd (int): Length of the MAC key in bytes.
        t (int): Length of zero-padding in bytes.
        nonce_len (int): Length of the nonce in bytes.
        msg_len (int): Total length of the message in bytes.
        h (list[bytes]): List of nonces used for each locker.
        ctxt (list[bytes]): List of ciphertexts corresponding to each locker.
        tag (bytes): Authentication tag.
        zeros (bytes): Zero padding (for faster comparison).
    '''

    def __init__(
            self,
            sample_len: int = 192,
            locker_num: int = 3500,
            key_len: int = 128,
            mac_key_len: int = 128,
            padding_len: int = 128,
            nonce_len: int = 64,
            # seed: int = None
    ) -> None:
        '''
        Initializes the Fuzzy Extractor with given parameters.
        
        Args:
            sample_len (int): Length of the input sample in bits.
            locker_num (int): Number of lockers.
            key_len (int): Desired length of the key to generate in bits.
            mac_key_len (int): Length of MAC key for authentication in bits.
            padding_len (int): Length of zero padding in bits.
            nonce_len (int): Length of nonce used for each locker in bytes.
            seed (int, optional): Seed for reproducibility (currently unused, TODO).
        '''

        # System parameters
        self.m = sample_len
        self.ell = locker_num
        self.xi = key_len // 8
        self.lbd = mac_key_len // 8
        self.t = padding_len // 8
        self.nonce_len = nonce_len

        # Total message length (0^t || R || R_1)
        self.msg_len = self.xi + self.lbd + self.t

        # hashing algorithm
        self.digest = sha384

        # Pre-define variables
        self.ctxt = [bytes(0) for _ in range(self.ell)]
        self.joint_ctxt = bytes(0)
        self.tag = bytes(0)
        self.h = []
        self.positions = None

        # Pre-compute zero string for faster comparison
        self.zeros = bytes([0]*self.t)

        logging.info("FuzzyExtractor initialized with %d lockers.", self.ell)



    def generate(
            self,
            w: bytes
    ) -> bytes:
        '''
        Generates a cryptographic key and encodes it using noisy samples.
        
        Args:
            w (bytes): A large sample used to encode the key.
        
        Returns:
            bytes: Generated cryptographic key.
        '''


        # Generate keys from OS randomness
        key = token_bytes(self.xi)
        tag_key = token_bytes(self.lbd)

        # Construct message
        msg = self.zeros + key + tag_key

        # Generate \ell nonces of length `nonce_len`
        self.h = [token_bytes(self.nonce_len) for _ in range(self.ell)]

        # Generate \ell subsample positions
        self.positions = np.random.choice(len(w), (self.ell, self.m), replace=True)

        # Begin locking with samples w_i
        for i in range(self.ell):
            # Construct a subsample
            w_i = bytes(itemgetter(*self.positions[i])(w))
            # Make uniform using HMAC
            pad = hmac.digest(key=w_i, msg=self.h[i], digest=self.digest)
            # One Time Pad
            self.ctxt[i] = xor_bytes(msg, pad)

        # Join ciphertexts
        self.joint_ctxt = b''.join(self.ctxt)

        # Calculate tag TODO add seed
        self.tag = sha256(self.joint_ctxt + tag_key).digest()
        # self.tag = hmac.digest(key=tag_key, msg=self.joint_ctxt, digest=sha256)

        return key


    def reproduce(
            self,
            w_: list[bytes]
    ) -> bytes:
        '''
        Attempts to recover the cryptographic key using noisy samples.
        
        Args:
            w_ (list[bytes]): List of samples used to recover the key.
        
        Returns:
            bytes: The reproduced key if successful; None otherwise.
        '''
        # Begin opening locks
        for i in range(self.ell):
            # Construct a subsample
            w_i = bytes(itemgetter(*self.positions[i])(w_))
            # Attempt to recreate the pad
            pad_ = hmac.digest(key=w_i, msg=self.h[i], digest=self.digest)
            # One Time Pad decrypt
            msg_ = xor_bytes(self.ctxt[i], pad_)

            # Test for validity
            if msg_[:self.t] == self.zeros:
                # Leading t bits are zeros
                key = msg_[self.t:(self.t + self.xi)]
                tag_key = msg_[(self.t + self.xi):]

                # tag = hmac.digest(key=tag_key, msg=self.joint_ctxt, digest=sha256)
                tag = sha256(self.joint_ctxt + tag_key).digest()

                if tag == self.tag:
                    return key

        return None


    def reproduce_multithreaded(
            self,
            w: list[bytes],
            num_processes: int = 1
    ) -> bytes:
        '''
        TODO
        '''

        finished = multiprocessing.Array('b', False)
        split = np.array_split(list(range(self.ell)), num_processes)
        finished = multiprocessing.Manager().list([None for _ in range(num_processes)])

        processes = []

        for process_id in range(num_processes):
            pr = multiprocessing.Process(
                target=self.reproduce_process,
                args=(w, split[process_id], finished, process_id)
            )
            processes.append(pr)
            pr.start()

        for process in processes:
            process.join()

        if any(finished):
            return next(result for result in finished if result is not None)

        return None


    def reproduce_process(
            self,
            w: list[bytes],
            indices: list[int],
            finished,
            process_id: int
    ) -> None:
        '''
        TODO
        '''
        update = 0

        for index in indices:
            pad = hmac.digest(key=w[index], msg=self.h[index], digest=self.digest)
            msg = xor_bytes(self.ctxt[index], pad)

            # Test for validity
            if msg[:self.t] == self.zeros:
                # Leading t bits are zeros
                key = msg[self.t:(self.t + self.xi)]
                tag_key = msg[(self.t + self.xi):]

                tag = hmac.digest(key=tag_key, msg=self.joint_ctxt, digest=self.digest)

                if tag == self.tag:
                    finished[process_id] = key
                    return

                update += 1
                if update >= 50:
                    if not any(finished):
                        update = 0
                    else:
                        return



def main(num_rep, locker_num):
    '''
    Simulates the Fuzzy Extractor with APUF-based samples.
    
    Args:
        num_rep (int): Number of reproduction attempts.
        LOCKER_NUM (int): Number of lockers used in Fuzzy Extractor.
    '''

    # Simulate Arbiter PUFs
    logging.info("Generating Arbiter PUFs...")
    apuf = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)
    # apuf_adversary = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)

    # Load challenges
    try:
        challenges = np.load("challenges/1_mil_challenges.npy")
        logging.info("Challenges loaded successfully.")
    except FileNotFoundError:
        logging.error("Challenge file not found. Ensure the path is correct.")
        raise


    fe = FuzzyExtractor(locker_num=locker_num)

    # Server obtains sample W
    t = time.perf_counter()
    server_sample = bytes(get_noisy_responses(1, [apuf], challenges, 0, 0.05*0.1))
    t1 = time.perf_counter()
    logging.info("Reading W took %.4f seconds.", t1 - t)

    # Server runs Gen(W) to obtain a session key and helper data
    t = time.perf_counter()
    key = fe.generate(server_sample)
    t1 = time.perf_counter()
    logging.info("Gen took %.4f seconds.", t1 - t)
    logging.debug("Generated key: %s", key)


    rep_times = []
    match_num = 0

    logging.info("Running Rep %d times", num_rep)
    for _ in range(num_rep):
        # User obtains a fresh sample W'
        user_sample = bytes(get_noisy_responses(1, [apuf], challenges, 0, 0.05*0.1))


        t = time.perf_counter()
        key_ = fe.reproduce(user_sample)
        t1 = time.perf_counter()


        rep_times.append(t1 - t)
        if key == key_:
            match_num += 1


    logging.info("On average, reproduction took %.4f seconds.", np.mean(rep_times))
    # logging.info("Correctly recovered key %d/%d times.", match_num, num_rep)

    logging.info("Hashing to simulate AKE authentication")
    t = time.perf_counter()

    nonce = token_bytes(8) # 64 bit nonce
    h1 = sha256(nonce + fe.joint_ctxt + b'user' + b'server' + key).digest()
    h2 = sha256(nonce + fe.joint_ctxt + b'user' + b'server' + key).digest()

    session_key = sha256(fe.joint_ctxt + b'user' + b'server' + key).digest()
    t1 = time.perf_counter()
    print(h1, h2, session_key)
    logging.info("Generating hashes took %.4f seconds.", t1 - t)



    return match_num


if __name__ == "__main__":
    logging.info("Starting Fuzzy Extractor experiments...")
    logging.info("Total number of matches: %d/%d", sum(main(1, 3500) for i in range(50)), 50)
    logging.info("Experiments complete.")
    logging.info("====================\n")
