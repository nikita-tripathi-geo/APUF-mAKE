# APUF-mAKE

**Fast and post-quantum mutually authenticated key exchange (mAKE) for Arbiter PUFs**

This is a demo implementation of a novel mutually authenticated key exchange (mAKE) protocol that uses (noisy) responses from Arbiter PUFs (APUFs). It includes:

- A **Fuzzy Extractor** to derive stable cryptographic keys from noisy APUF responses.  
- A **server** and **user (client)** implementation of the registration and AKE phases over a simple TCP socket interface.  
- Utilities for challenge loading, byte-packing, and network I/O.

---

## 🚀 Features

- **PUF-based secrets**: No pre-distributed keys—only PUF measurements.  
- **Fuzzy Extractor** for error correction and helper-data generation.
- **Mutual authentication** via fresh nonces and HMAC/SHA-256 hashes.
- **Post-quantum security**: The protocol only uses hashing and bit-wise XOR operations, resulting in fast computation and post-quantum security in the random oracle (RO) model.
- **Modular**: Easily swap in your own PUF simulator (e.g., [APUF-simulation](https://github.com/nikita-tripathi-geo/APUF-simulation)) or any other noisy source (biometrics, quantum phenomena, etc.).

---

## 📦 Installation

1. **Clone** this repository:  
   ```bash
   git clone https://github.com/nikita-tripathi-geo/APUF-mAKE.git
   cd APUF-mAKE

2. **Create a virtual environment** (recommended):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   > *`requirements.txt` includes packages like `numpy` and `apuf` (for apuf simulation).*

4. **Prepare challenge files**:
   Place your `.npy` challenge arrays in the `challenges/` folder (e.g. `1_mil_challenges.npy`).
   You can generate them via the `challenges` module of the `apuf` package (which you have installed above).

   ```python
   from challenges import generate_k_challenges
   import numpy as np

   chals = generate_k_challenges(1_000_000, 128, seed=42)
   np.save("challenges/1_mil_challenges.npy", chals)
   ```

   Challenge generation takes some time. If you don't want to wait too long, you may choose to use my pre-generated challenges, which can be downloaded using `git lfs`.

   ```bash
   git lfs pull --include="challenges/1_mil_challenges.npy"
   ```
   > The challenge file (1 million challenges) is approximately 1.03 GB.

---

## 💡 Usage

All scripts assume Python 3.11+.

### 1. Registration Phase

1. **Server** (listen mode):

   ```bash
   python server.py <IP> <PORT>
   ```
2. **Client**:

   ```bash
   python user.py <IP> <PORT>
   ```

On execution:

* The **client** measures an APUF sample `W` and sends it to the server (registration).
* The **server** stores `W` in `registered_W.bin`.

### 2. AKE Phase

With the same socket:

1. **Server** calls `server_ake()`, loading `registered_W.bin`, running Gen, and sending helper data + nonce.
2. **Client** calls `user_ake()`, re-measures `W′`, runs Rep, authenticates via SHA-256 hashes, and derives the shared session key.
3. **Both** derive the final session key `K = SHA-256(helper ∥ ID_A ∥ ID_B ∥ raw_key)`.

You’ll see logs for each step and the final `Session key: …` printed on both ends.

---

## 🔐 Cryptographic Background

TODO

---

## ⏱️ Benchmarks

TODO

Benchmarks for each parameter (locker size $\ell$).

---

## 📂 Repository Structure

```
APUF-mAKE/
├── challenges/            # Precomputed .npy challenge arrays
├── fuzzy_extractor.py     # Fuzzy Extractor implementation
├── server.py              # Server-side mAKE protocol
├── user.py                # Client-side mAKE protocol
├── socket_helper.py       # Length-prefixed TCP I/O utilities
├── utilities.py           # Byte-wise XOR, bit-packing functions
├── picking_ell.py         # (helper for parameter selection)
├── pylintrc               # Linting rules
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

---

## 🤝 Contributing

1. Fork this repo.
2. Create a feature branch: `git checkout -b feature/foo`.
3. Commit your changes: `git commit -am 'Add foo'`.
4. Push to your branch: `git push origin feature/foo`.
5. Open a Pull Request.

Please ensure all new code is covered by basic tests and format it with `black`.

---

## 📜 License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 📬 Contact

Please contact me with any questions/suggestions via GitHub.
