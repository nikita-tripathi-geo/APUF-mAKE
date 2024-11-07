#!/usr/bin/python3

# IMPORTS
from secrets import randbits, token_bytes
import multiprocessing
import hmac
from hashlib import sha3_384, sha384
import time

# from apuf_simulation import generate_n_APUFs, get_noisy_responses
from utilities import xor_bytes

# Developed for Python 3.12.6


class FuzzyExtractor:

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
        '''

        # System parameters
        self.m = sample_len
        self.ell = locker_num
        self.xi = key_len
        self.lbd = mac_key_len
        self.t = padding_len
        self.nonce_len = nonce_len

        # Total message length (0^t || R || R_1)
        self.msg_len = self.xi + self.lbd + self.t

        # hashing algorithm
        # self.hash = sha384

        # Generating a CRS: \ell nonces of length `nonce_len`
        self.h = [randbits(self.nonce_len) for _ in range(self.ell)]

        # Pre-define ciphertext list and tag
        self.ctxt = [bytes(0) for _ in range(self.ell)]
        self.tag = bytes(0)

        self.zeros = bytes([0]*self.t)


    def generate(
            self,
            w: list[bytes]
    ) -> bytes:
        '''
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
        self.tag = hmac.digest(key=R_1, msg=sum(self.ctxt), digest=sha3_384)

        return R

    def reproduce(
            self,
            w_: list[bytes]
    ) -> bytes:
        '''
        TODO
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
                print(f"Lengths: R: {len(R)}, R_1: {len(R_1)}")

                tag = hmac.digest(key=R_1, msg=sum(self.ctxt), digest=sha3_384)

                if tag == self.tag:
                    return R

        return None


# def main(num_rep, LOCKER_NUM):

#     # Create seeds for challenges TODO this is hard-coded, find a better way to do this
#     # challenge_seeds = [random.SystemRandom().randint(0, 2**32 -1) for _ in range(3_500)]
#     APUF = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)
#     APUF_adversary = generate_n_APUFs(1, 129, weight_mean=0, weight_stdev=0.05)
#     challenges = np.load("../3500_challenges.npy")[:LOCKER_NUM]

#     # challenges = generate_k_n_challenges(LOCKER_NUM, 192, 129, seed=random.SystemRandom().randint(0, 2**32 -1))
#     #np.save("3500_challenges.npy", challenges)

#     # resp1 = get_noisy_responses(APUF, challenges, noise_mean=0, noise_std=(0.1*0.05))
#     # c1 = [resp1[j][0] for j in range(len(resp1))]
#     c1 = np.concatenate([get_noisy_responses(1, [APUF], chal, noise_mean=0, noise_std=(0.05*0.1)) for chal in challenges  ])

#     print(c1.shape)

#     PASSWORD_LENGTH = 0
#     PASSWORD = np.random.default_rng().integers(low=0, high=1, endpoint=True, size=(PASSWORD_LENGTH), dtype=np.uint8)
#     print(f"Password: {PASSWORD}")

#     t1 = time.time()
#     # fe = FuzzyExtractor(l=3_500, file_prefix="test_APUF_new", pwd_len=PASSWORD_LENGTH)
#     fe = FuzzyExtractor(l=LOCKER_NUM, file_prefix="debug/test_APUF_new", pwd_len=PASSWORD_LENGTH)
#     t2 = time.time()
#     print(f"Initialized (generated lpn arrays & GF(2^128)) in {t2 - t1} seconds")

#     a = fe.gen(
#         c1,
#         pwd=PASSWORD
#     )
#     t3 = time.time()
#     print(f"Ran GEN in {t3 - t2} seconds")

#     results = []

#     for t in range(num_rep):

#         ct = np.concatenate([get_noisy_responses(1, [APUF], chal, noise_mean=0, noise_std=(0.05*0.1)) for chal in challenges  ])
#         # ct = np.concatenate([get_noisy_responses(APUF_adversary, chal, noise_mean=0, noise_std=(0.05*0.1)) for chal in challenges  ])

#         print(ct.shape, " Shape of Rep samples (responses)")
#         np.savetxt("c1.txt", c1)
#         np.savetxt("ct.txt", ct)

#         # print(f"Distance from original: {1}")

#         t1 = time.time()
#         b = fe.rep_parallel(
#             ct,
#             pwd=PASSWORD,
#             num_processes=1
#             # num_processes=multiprocessing.cpu_count()
#         )
#         # b = fe.rep_parallel(
#         #     ct[5],
#         #     pwd=PASSWORD,
#         #     num_processes=multiprocessing.cpu_count() // 3
#         # )
#         results.append(b)
#         t2 = time.time()
#         print(f"Ran REP parallel in {t2 - t1} seconds")




#     print(a)
#     print(len([r for r in results if r])/len(results))


#     print("no problems so far")


# if __name__ == '__main__':

#     main(
#         num_rep=1,
#         LOCKER_NUM=3200
#         )



