import numpy as np
import random


def generate_n_APUFs(n: int, d: int,
                    weight_mean: float = 0.0,
                    weight_stdev: float = 0.05) -> np.ndarray:
    """Generate weight vectors for `n` Arbiter PUFs.

    Samples n weight vectors of length `d` from a normal distribution.

    Args:
        n (int): Number of PUF instances to generate.
        d (int): Dimension of each weight vector.
        weight_mean (float): Mean of the normal distribution. Defaults to 0.0.
        weight_stdev (float): Standard deviation of the normal distribution. Defaults to 0.05.

    Returns:
        np.ndarray: Array of shape (n, d) containing `n` weight vectors.
    """
    ws = np.random.normal(loc=weight_mean, scale=weight_stdev, size=(n, d))

    return ws


def generate_n_challenges(k: int, d: int, seed: int = None) -> np.ndarray:
    """Generate phase vectors (phi) for a set of APUF challenges.

    Each challenge is a binary vector of length `d`. This function
    maps random challenges to delay-based phase vectors.

    Args:
        k (int): Number of challenges.
        d (int): Length of each challenge (number of bits).
        seed (int, optional): PRNG seed for reproducibility. Defaults to None.

    Returns:
        np.ndarray: A phase matrix phi of shape (d, k), where each
            column corresponds to the transformed challenge.
    """

    # Generate binary challenges
    if seed is not None:
        rng = np.random.default_rng(seed=seed)
        chals = rng.integers(0, 2, (k, d))
    else:
        chals = np.random.randint(0, 2, (k, d))

    # Map {0,1} -> {+1,-1}
    chals_prime = 1 - 2 * chals

    # Convert to phi
    phi = np.ones((k, d))

    for chal in range(k):
        for i in range(d):
            for j in range(i, d):
                phi[chal][i] *= chals_prime[chal][j]

    phi = np.transpose(phi)

    # set last bit to 1 (last bit of psi has to be 1)
    phi[-1] = np.ones(k)

    return phi


def generate_k_n_challenges(x:int, k:int, d: int, seed : int = None):
    """Generate `x` sequences of `k` random challenges.

    Args:
        x (int): Number of challenge sequences.
        k (int): Number of challenges per sequence.
        d (int): Length of each challenge.
        seed (int, optional): PRNG seed for reproducibility. Defaults to None.

    Returns:
        np.ndarray: Array of shape (x, d, k) containing feature matrices
            for each locker.
    """

    # Generate binary challenges
    if seed is not None:
        rng = np.random.default_rng(seed=seed)
        chals = rng.integers(0, 2, (x, k, d))
    else:
        chals = np.random.randint(0, 2, (x, k, d))

    chals_prime = 1 - 2 * chals

    phi = np.ones((x, k, d))

    for locker in range(x):
        for chal in range(k):
            for i in range(d):
                for j in range(i, d):
                    phi[locker][chal][i] *= chals_prime[locker][chal][j]

    result = np.transpose(phi, (0, 2, 1))
    for i in range(x):
        result[i][-1] = np.ones(k)

    return result

def determine_response(delay: float) -> int:
    """Threshold delay to obtain a response bit."""
    if delay > 0:
        return 1
    return 0

# Vectorized thresholding function. Works on float ndarrays.
determine_response_vectorized = np.vectorize(determine_response)

def get_responses(weights: np.ndarray,
                  phis: np.ndarray) -> np.ndarray:
    """Compute multi-bit response to a sequence of challenges.

    Args:
        weights (np.ndarray): Weight vector of APUF.
        phi (np.ndarray): Challenge (phase vector) sequence.

    Returns:
        np.ndarray: Multi-bit binary response.
    """
    delays = weights @ phis
    return determine_response_vectorized(delays)


def norm_hamming_distances(responses: np.ndarray):
    """Compute fractional Hamming distances between all pairs of responses.
    TODO remove

    Args:
        responses (np.ndarray): 2D binary array of shape (m, r), where m is number
            of response vectors and r is their length.

    Returns:
        list[float]: List of normalized Hamming distances between each pair.
    """
    distances = []

    for i in range(len(responses)):
        for j in range(i+1, len(responses)):
            hd = np.count_nonzero(responses[i] ^ responses[j])
            hd = hd/len(responses[i])
            distances.append(hd)

    return distances


def get_noisy_responses(xor_num: int,
                        ws: np.ndarray,
                        ps: np.ndarray,
                        noise_mean: float,
                        noise_std: float) -> np.ndarray:
    """Generate noisy APUF/XOR-PUF responses.

    Args:
        xor_num (int): Number of APUF instances in XOR-PUF. Use `1` if simulating APUF.
        weights (np.ndarray): Weight vectors.
        phi (np.ndarray): Sequence of challenges (phase vectors).
        noise_mean (float): Mean of Gaussian noise.
        noise_std (float): Standard deviation of Gaussian noise.

    Returns:
        np.ndarray: Binary response vector after noisy measurements.
    """
    responses = []

    for i in range(xor_num):

        noise = np.random.normal(noise_mean, noise_std, ws[i].shape)

        resp = (ws[i] + noise) @ ps

        responses.append( determine_response_vectorized(resp))

    resp = responses[0]

    # Only if using XOR-PUF
    for i in range(1, xor_num):
        resp ^= responses[i]

    return resp


def main():

    APUF_NUM = 1
    RESP_LEN = 192
    MEAN = 0
    STDEV = 0.05
    GAMMA = 0.1
    CHAL_LENGTH = 128+1
    XOR_NUM = 1
    # 0 <= gamma <= 1
    # gamma = 0 -> noiseless responses
    # gamma = 1 -> very noisy (?) response

    w = [generate_n_APUFs(APUF_NUM, CHAL_LENGTH, weight_mean=MEAN, weight_stdev=STDEV) for _ in range(XOR_NUM)]
    # p = generate_n_challenges(RESP_LEN, CHAL_LENGTH)
    p = generate_n_challenges(RESP_LEN, CHAL_LENGTH, seed=random.SystemRandom().randint(0, 2**32 - 1))
    # resp = get_responses(w, p)

    k_dist = []
    for k in range(20):
        resp = get_noisy_responses(XOR_NUM, w, p, noise_mean=MEAN, noise_std=(GAMMA * STDEV))

        #print(resp.shape)

        d = np.array(norm_hamming_distances(resp))
        #print(type(d))

        k_dist.append(d)

    dist = sum(k_dist)/(k+1)

    #print(k_dist)
    #_ = plt.hist(dist, bins='auto')

    #plt.show()

    filename = f"APUF_distances_resp_{RESP_LEN}_gamma_{GAMMA}"

    # with open(filename+'.pkl', 'wb') as f:
    #     pickle.dump(dist, f)

    with open(filename+'.txt', 'w') as f:
        for i in dist:
            f.write(f"{i}\n")

    m = np.mean(dist)
    v = np.var(dist)

    degrees_of_freedom = (1 - m) * m / v
    entropy = (-m * np.log2(m) - (1 - m) * np.log2(1 - m)) * degrees_of_freedom

    print(len(dist))
    print(f"mean: {m}\nvar: {v}\ndf: {degrees_of_freedom} \nentropy: {entropy}")

    return entropy

if __name__ == '__main__':
    print(np.mean([main() for _ in range(3)]))
