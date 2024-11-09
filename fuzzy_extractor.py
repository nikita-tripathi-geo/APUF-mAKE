#!/usr/bin/python3

# IMPORTS
from secrets import token_bytes
import multiprocessing
import hmac
from hashlib import sha3_384, sha384
import time

import numpy as np
from utilities import xor_bytes
from apuf_simulation import generate_n_APUFs, get_noisy_responses

# Developed for Python 3.12.6


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
            seed: int = None
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
        # self.hash = sha384

        # Generating a CRS: \ell nonces of length `nonce_len`
        self.h = [token_bytes(self.nonce_len) for _ in range(self.ell)]

        # Pre-define ciphertext list and tag
        self.ctxt = [bytes(0) for _ in range(self.ell)]
        self.tag = bytes(0)

        # Pre-compute zero string for faster comparison
        self.zeros = bytes([0]*self.t)


    def generate(
            self,
            w: list[bytes]
    ) -> bytes:
        '''
        Generates a cryptographic key and encodes it using noisy samples.
        
        Args:
            w (list[bytes]): List of samples used to encode the key.
        
        Returns:
            bytes: Generated cryptographic key.
        '''


        # Generate keys from OS randomness
        R = token_bytes(self.xi)
        R_1 = token_bytes(self.lbd)

        # Construct message
        msg = self.zeros + R + R_1

        # Begin locking with samples w_i
        for i in range(self.ell):
            pad = hmac.digest(key=w[i], msg=self.h[i], digest=sha3_384)
            self.ctxt[i] = xor_bytes(msg, pad)

        # Calculate tag
        self.tag = hmac.digest(key=R_1, msg=b''.join(self.ctxt), digest=sha3_384)

        return R


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
            pad_ = hmac.digest(key=w_[i], msg=self.h[i], digest=sha3_384)
            msg_ = xor_bytes(self.ctxt[i], pad_)

            # Test for validity
            if msg_[:self.t] == self.zeros:
                # Leading t bits are zeros
                R = msg_[self.t:(self.t + self.xi)]
                R_1 = msg_[(self.t + self.xi):]

                tag = hmac.digest(key=R_1, msg=b''.join(self.ctxt), digest=sha3_384)

                if tag == self.tag:
                    return R

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
            pad = hmac.digest(key=w[index], msg=self.h[index], digest=sha3_384)
            msg = xor_bytes(self.ctxt[index], pad)

            # Test for validity
            if msg[:self.t] == self.zeros:
                # Leading t bits are zeros
                R = msg[self.t:(self.t + self.xi)]
                R_1 = msg[(self.t + self.xi):]

                tag = hmac.digest(key=R_1, msg=b''.join(self.ctxt), digest=sha3_384)

                if tag == self.tag:
                    finished[process_id] = R
                    return

                update += 1
                if update >= 100:
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

    APUF = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)
    APUF_adversary = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)
    challenges = np.load("./5000_challenges.npy")[:locker_num]


    fe = FuzzyExtractor()

    # Server obtains sample W
    server_sample = [
        bytes(get_noisy_responses(1, [APUF], c, 0, 0.05*0.1 )) for c in challenges
    ]

    # Server runs Gen(W) to obtain a session key and helper data
    t = time.perf_counter()
    key = fe.generate(server_sample)
    t1 = time.perf_counter()

    # print(f"Gen took {t1-t} seconds")
    # print(f"Key = {key}")

    rep_times = []
    match_num = 0

    for usr_attempt in range(num_rep):
        # User obtains a fresh sample W'
        user_sample = [
            bytes(get_noisy_responses(1, [APUF], c, 0, 0.05*0.1 )) for c in challenges
        ]

        t = time.perf_counter()
        key_ = fe.reproduce_multithreaded(user_sample, num_processes=12)
        # key_ = fe.reproduce(user_sample)
        t1 = time.perf_counter()

        # print(f"Rep took {t1-t} seconds")
        # print(f"Key = {key_}")

        rep_times.append(t1 - t)
        # print(
        #     f"Attempt id: {usr_attempt}",
        #     "Session keys match!" if key == key_ else "Session key mismatch"
        # )
        if key == key_:
            match_num += 1


    print(np.mean(rep_times))
    print(match_num)



if __name__ == "__main__":
    # for _ in range(15):
    #     main(15, 3500)
    main(1, 5000)
