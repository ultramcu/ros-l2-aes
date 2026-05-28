# ROS-L2 — Layer-2 AES-CBC encryption for ROS topics

Companion code for:

> Tanadechopon T., Kasemsontitum B.
> **"Proposed Technique for Data Security with the AES Algorithm in Robot Operating System."**
> *2023 27th International Computer Science and Engineering Conference (ICSEC).*
> [ieeexplore.ieee.org/document/10329645](https://ieeexplore.ieee.org/document/10329645)

A small ROS catkin package (`crypto`) that wraps `std_msgs/String` payloads in a JSON envelope and encrypts the data field with AES-CBC before publishing — letting two ROS nodes that share a key talk over an otherwise unencrypted ROS Master without exposing message content to passive observers (Wireshark port-mirror, MITM, etc.).

## Layout

```
ros-l2-aes/                           # github.com/ultramcu/ros-l2-aes
├── include/
│   ├── crypto.h                      # AES + hex API (see comments at top)
│   └── type.h                        # ROS message TYPE codes
├── src/
│   ├── crypto.cpp                    # AES-CBC implementation (OpenSSL legacy AES_* API)
│   └── main.cpp                      # ROS node + pub/sub/image-stream entrypoints
├── config/
│   ├── keys.example.h                # template — copy to keys.h and fill in
│   └── keys.h                        # YOUR KEYS — git-ignored, not committed
├── package.xml
├── CMakeLists.txt
├── README.md
├── LICENSE
└── CITATION.cff
```

The repo is a self-contained ROS catkin package — clone it into any catkin workspace's `src/` directory:

```
your_catkin_ws/
└── src/
    └── ros-l2-aes/                   # clone here
```

## Build

Requires ROS Noetic (Ubuntu 20.04). On Apple Silicon, the experiment in the paper was reproduced under Parallels Desktop running Ubuntu 20.04 ARM64; the ARMv8 Cryptography Extensions are forwarded to the guest so OpenSSL AES is hardware-accelerated.

```bash
# 1. Clone into a catkin workspace:
cd ~/catkin_ws/src
git clone https://github.com/ultramcu/ros-l2-aes.git

# 2. Provide your own keys (one-time setup):
cd ros-l2-aes
cp config/keys.example.h config/keys.h
# Edit keys.h, replace placeholder bytes with output of
#   head -c 16 /dev/urandom | xxd -i   # for AES-128 key
#   head -c 32 /dev/urandom | xxd -i   # for AES-256 key

# 3. Build:
cd ~/catkin_ws
catkin_make
source devel/setup.bash
```

## Run

The `l2topic` node dispatches on its first argument:

| Subcommand | Effect |
|---|---|
| `l2topic pub <topic> <type> <data>` | Publish a single encrypted message of `<type>` on `<topic>` |
| `l2topic pub100 <topic> <type> <data>` | Publish 100 messages (timing benchmark) |
| `l2topic pubimg <topic>` | Stream webcam frames, encrypted, to `<topic>` |
| `l2topic pubimg2 <topic>` | Streaming variant with pipeline threading |
| `l2topic echo <topic>` | Subscribe, decrypt, print |

The JSON envelope shape (after decryption) is:

```json
{ "Type": 1, "Time": 1688054842, "Data": "<hex-encoded ciphertext>" }
```

`Type` codes are defined in `include/type.h` (e.g. `1 = eString`).

## Reproducing the paper measurements

The paper reports `createPubMessageFile` wall-clock time across image / text payloads (100 iterations each) for AES-128 vs AES-256. On the Pi-class hardware used for the original run, AES-128 and AES-256 produced statistically indistinguishable wall-clock times (σ ≈ 25% over 100 iterations dominates the 4-extra-round delta of AES-256 vs AES-128). The same convergence appears when re-running on Apple Silicon under Parallels — the wrapping pipeline (file I/O, JSON envelope, hex encode, ROS publish) dominates total time, and the AES rounds themselves run through the ARMv8 hardware crypto path either way.

## Layout of message flow

```
+---------------+        +-----------------+        +---------------+
|  Publisher    |        |  ROS Topic      |        | Subscriber    |
|               | publish|  std_msgs/String| subscribe              |
| cv::Mat       +---+--->+ "encrypted_topic"+----+-->+ JSON {Type,   |
|   ↓ imencode  |   |    +-----------------+    |   |   Time, Data} |
| vector<uint8> |   |                            |   |    ↓ extract  |
|   ↓ hex       |   |    eavesdropper sees:      |   | hex Data      |
|  AES-CBC      |   |    {"Data":"C1055E…",      |   |    ↓ unhex    |
|   ↓ bytesToHex|   |     "Time":…, "Type":1}    |   | AES-CBC       |
| JSON envelope +---+    (ciphertext only)       +---+    ↓ decrypt  |
+---------------+                                    | cv::Mat       |
                                                     +---------------+
```

## License

[MIT](LICENSE) © 2023 Tanadechopon & Kasemsontitum; cleanup © 2026 ultramcu.

## Citation

See [`CITATION.cff`](CITATION.cff) for a machine-readable citation; in BibTeX:

```bibtex
@inproceedings{tanadechopon2023ros,
  author    = {Tanadechopon, Teerapong and Kasemsontitum, Boontariga},
  title     = {Proposed Technique for Data Security with the AES Algorithm in Robot Operating System},
  booktitle = {2023 27th International Computer Science and Engineering Conference (ICSEC)},
  year      = {2023},
  doi       = {10.1109/ICSEC59635.2023.10329645},
  url       = {https://ieeexplore.ieee.org/document/10329645}
}
```
