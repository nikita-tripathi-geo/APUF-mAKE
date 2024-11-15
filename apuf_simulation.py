import random
import numpy as np
import matplotlib.pyplot as plt


def generate_n_APUFs(n: int, weight_length: int,
    weight_mean: float = 0, weight_stdev: float = 1):
    """_summary_

    Args:
        n (int): _description_
        weight_length (int): _description_
        weight_mean (float, optional): _description_. Defaults to 0.
        weight_stdev (float, optional): _description_. Defaults to 1.

    Returns:
        np.ndarray: _description_
    """
    ws = np.random.normal(loc=weight_mean, scale=weight_stdev, size=(n, weight_length))

    return ws


def generate_n_challenges(n:int, chal_length: int, seed : int = None):
    """_summary_

    Args:
        n (int): _description_
        chal_length (int): _description_

    Returns:
        np.ndarray: _description_

    """

    # chals = np.random.randint(0, 2, (chal_length, n))
    if seed is not None:  # TODO: change later to "best practice" version
        np.random.seed(seed)

    chals = np.random.randint(0, 2, (n, chal_length))

    # chals = 1 - 2 * chals
    chals_prime = 1 - 2 * chals

    phi = np.ones((n, chal_length))

    for chal in range(n):
        for i in range(chal_length):
            for j in range(i, chal_length):
                phi[chal][i] *= chals_prime[chal][j]

    phi = np.transpose(phi)

    # set last bit to 1 (last bit of psi has to be 1)
    # chals[-1] = np.ones(n)
    phi[-1] = np.ones(n)

    # return chals
    return phi

def generate_k_n_challenges(k:int, n:int, chal_length: int, seed : int = None):
    """_summary_

    Args:
        k (int): number of lockers
        n (int): _description_
        chal_length (int): _description_

    Returns:
        np.ndarray: _description_

    """

    # chals = np.random.randint(0, 2, (chal_length, n))
    if seed is not None:  # TODO: change later to "best practice" version
        np.random.seed(seed)

    chals = np.random.randint(0, 2, (k, n, chal_length))

    # chals = 1 - 2 * chals
    chals_prime = 1 - 2 * chals

    phi = np.ones((k, n, chal_length))

    for locker in range(k):
        for chal in range(n):
            for i in range(chal_length):
                for j in range(i, chal_length):
                    phi[locker][chal][i] *= chals_prime[locker][chal][j]

    result = np.transpose(phi, (0, 2, 1))
    for i in range(k):
        # result[i]  = np.transpose(phi[i])

        # set last bit to 1 (last bit of psi has to be 1)
        # chals[-1] = np.ones(n)
        result[i][-1] = np.ones(n)

    # return chals
    return result



# def generate_n

def determine_response(delay: float) -> np.int8:
    return np.int8(1) if delay > 0 else np.int8(0)
    # if delay > 0:
    #     return 1
    # return 0

determine_response_vectorized = np.vectorize(determine_response)

def get_responses(ws, ps):
    """_summary_

    Args:
        ws (_type_): _description_
        ps (_type_): _description_

    Returns:
        _type_: _description_
    """
    return determine_response_vectorized(ws @ ps)


def norm_hamming_distances(responses: np.ndarray):
    """_summary_

    Args:
        responses (np.ndarray): _description_

    Returns:
        list[float]: _description_
    """
    distances = []
    print(responses)

    for i in range(len(responses)):
        for j in range(i+1, len(responses)):
            hd = np.count_nonzero(responses[i] ^ responses[j])
            hd = hd/len(responses[i])
            distances.append(hd)

    return distances


def get_noisy_responses(
    xor_num: int,
    ws,  ps: np.ndarray,
    noise_mean: float, noise_std: float) -> np.ndarray:
    """
    blablabla
    """

    # responses = np.zeros(ps.shape, dtype=np.int64)
    responses = []


    for i in range(xor_num):

        noise = np.random.normal(noise_mean, noise_std, ws[i].shape)

        resp = (ws[i] + noise) @ ps

        responses.append( determine_response_vectorized(resp))

    resp = responses[0]
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
