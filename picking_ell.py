"""TODO"""

from itertools import combinations
import numpy as np
from apuf import APUF, Response

# Generate 10 APUFs
apufs = [APUF(128) for _ in range(10)]

# Generate 1_000_000 challenges
chals = np.load("challenges/1_mil_challenges.npy")

# PUF responses - measure the each PUF 20 times
all_responses: list[list[Response]] = []

for puf in apufs:
    responses = []
    for i in range(20):
        responses.append(puf.get_responses(chals, 0.0, 0.005))

    all_responses.append(responses)

# Sampe PUF distances
distances = []
for response in all_responses:
    for i, j in combinations(response, 2):
        hamming_dist = i.dist(j)/1_000_000
        distances.append(hamming_dist)

print(
    np.mean(distances),
    np.max(distances),
    np.count_nonzero(np.greater(distances, 0.043435)) / len(distances),
    len(distances),
)

# # Different PUFs
# distances = []

# for r1, r2 in combinations(all_responses, 2):
#     hamming_dist = r1 != r2
#     for i in range(20):
#         distances.append(np.count_nonzero(hamming_dist[i, :]) / 1_000_000)
# print(np.min(distances), np.mean(distances))


# a = apufs[1]
# print(puf.get_noisy_responses(1, [a], chals, 0, 0.005))
