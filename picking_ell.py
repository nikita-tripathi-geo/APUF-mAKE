"""
"""
from itertools import combinations
import numpy as np
import apuf_simulation as puf

# Generate 10 APUFs
apufs = puf.generate_n_APUFs(10, 129)

# Generate 1_000_000 challenges
chals = np.load("challenges/1_mil_challenges.npy")

# PUF responses - measure the each PUF 20 times
all_responses = []

for apuf in apufs:
    responses = np.zeros((20, 1_000_000))
    for i in range(20):
        responses[i, :] = puf.get_noisy_responses(1, [apuf], chals, 0, 0.005)

    all_responses.append(responses)

# Sampe PUF distances
distances = []
for response in all_responses:
    for (i, j) in combinations(response, 2):
        hamming_dist = np.count_nonzero(i != j)/1_000_000
        distances.append(hamming_dist)

print(np.mean(distances), np.max(distances), np.count_nonzero(np.greater(distances, 0.043435))/len(distances), len(distances))

# Different PUFs
distances = []

for (r1, r2) in combinations(all_responses, 2):
    hamming_dist = r1 != r2
    for i in range(20):
        distances.append(np.count_nonzero(hamming_dist[i, :])/1_000_000)
print(np.min(distances), np.mean(distances))




# a = apufs[1]
# print(puf.get_noisy_responses(1, [a], chals, 0, 0.005))
