# HTTP Digest Authentication · Part 1

[简体中文](README.md) | **English**

Part 1 of the DI31002 information security coursework: implement Digest authentication on an existing Python HTTP server and compare normal authentication with an intentionally backdoored version. This project is intended for coursework and local demonstrations.

## What this project does

- **Secure server**: valid credentials grant access to protected resources; missing or incorrect credentials receive `401 Unauthorized`.
- **Backdoored server**: normal authentication still works, while a designated compatibility branch permits password-independent access as a registered user to demonstrate an authentication flaw.
- **Two command-line clients**: prompt for a username and password, obtain an authentication challenge, and display the final HTTP status and response body.
- **Automated verification**: covers UTF-8 accounts, parameter parsing, URI binding, nonce expiry, replay, concurrency, cache limits, and real HTTP interactions.

Normal authentication uses SHA-256, `realm="DI31002"`, and `qop=auth`. Nonces expire after 300 seconds, are consumed after one successful authentication, and are stored in a cache capped at 4096 entries.

## Requirements

- Python **3.10+**.
- Git and access to this repository; the clone command below uses GitHub SSH.
- `urllib3>=2.3.0` for the base server. The added authentication code and clients use the Python standard library.

The commands below target Bash-compatible terminals on Ubuntu, Linux, and macOS. On Windows, you can follow the same steps in WSL.

## 1. Clone and install

```bash
git clone git@github.com:ganleming0-star/Information_sercurity_project_part1.git
cd Information_sercurity_project_part1/py-http-server-main

python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'urllib3>=2.3.0'
```

If you already downloaded the project, enter its `py-http-server-main` directory. Run all subsequent server, client, and test commands from that directory.

## 2. Configure local accounts

`passwords.txt` is a local file excluded from Git, so a fresh clone needs one. The following command creates sample accounts only when the file does not exist, preserving any existing file:

```bash
python - <<'PY'
from hashlib import sha256
from pathlib import Path

path = Path("passwords.txt")
if not path.exists():
    accounts = {"root": "password", "alice": "mushroom"}
    path.write_text(
        "".join(
            f"{username}:{sha256(password.encode('utf-8')).hexdigest()}\n"
            for username, password in accounts.items()
        ),
        encoding="utf-8",
    )
PY
```

The generated accounts are:

| Username | Original password |
| --- | --- |
| `root` | `password` |
| `alice` | `mushroom` |

Each line has the format `username:SHA256(password)`, where the stored value is the hexadecimal SHA-256 digest of the password's UTF-8 bytes. You may configure other accounts. The server reads the file at startup, so restart it after changes. An empty file provides no accounts that can authenticate.

## 3. Run the secure version

Start the server in your first terminal:

```bash
python start_server_digest.py
```

In a second terminal, enter the same server project directory, activate the environment, and run the client:

```bash
cd Information_sercurity_project_part1/py-http-server-main
source .venv/bin/activate
python client.py http://127.0.0.1:8080/README.md
```

Adjust the second terminal's `cd` command to your actual clone location. Enter `root` / `password` or `alice` / `mushroom` when prompted. The client displays `HTTP 200 OK` and the requested file's contents. Password characters are hidden during terminal input; an incorrect password receives `HTTP 401 Unauthorized`.

The URL argument is optional and defaults to `http://127.0.0.1:8080/`. You can also request other files in the server directory. For IPv6:

```bash
python client.py 'http://[::1]:8080/README.md'
```

## 4. Demonstrate the backdoor

Both startup scripts use port 8080, so run only one at a time. Press `Ctrl+C` in the first terminal to stop the secure server, then start the backdoored version:

```bash
python start_server_subverted.py
```

First verify normal authentication in the second terminal:

```bash
python client_subverted.py http://127.0.0.1:8080/README.md
```

A correct password is still required here. Then explicitly enable the backdoor demonstration:

```bash
python client_subverted.py --backdoor http://127.0.0.1:8080/README.md
```

Enter a registered username, such as `alice`, and any password. The client still prompts for a password, but the backdoor calculation does not use it.

| Request | Secure server | Backdoored server |
| --- | --- | --- |
| Correct account and password | `200` | `200` |
| Normal authentication with an incorrect password | `401` | `401` |
| Registered user with `--backdoor` | `401` | `200` |
| Unregistered username | `401` | `401` |

The `200` results assume the requested file exists; an authenticated request for a missing file still returns `404`. The backdoor activates only when `qop`, `nc`, and `cnonce` are all absent from the authentication header. That branch intentionally omits password binding.

## 5. Tests and character count

Stop the demonstration server with `Ctrl+C`, then run:

```bash
python -W error -m unittest discover -s tests -v
python tools/count_digest_chars.py
```

The full suite starts real loopback HTTP services. The supplied startup-script tests require IPv4, IPv6, and an available port 8080; a test is marked as skipped if the port is occupied or the address is unavailable.

The character-count tool counts every `(`, `:`, and `,` in the complete backdoored middleware source, including strings and comments. The current total is **47**, and a test enforces the character budget.

## Usage notes and troubleshooting

- **A browser or `curl --digest` cannot log in directly with the original password**: the coursework file stores only `SHA256(password)`. The provided clients prehash the input before calculating the Digest response. Use these clients; this step differs from ordinary Digest clients using the original password directly.
- **Missing `passwords.txt`**: run the account initialization command inside `py-http-server-main` and start the server from that directory.
- **Port already in use**: stop the other server instance first. The scripts listen on `127.0.0.1:8080` and `[::1]:8080`.
- **Missing `urllib3`**: activate `.venv` in the current terminal and install the dependency there.
- **Account changes have no effect**: restart the server to reload the password file.

## Main files

| File | Purpose |
| --- | --- |
| [digest_auth.py](py-http-server-main/py_http_server/middlewares/digest_auth.py) | Secure authentication middleware. |
| [digest_auth_subverted.py](py-http-server-main/py_http_server/middlewares/digest_auth_subverted.py) | Backdoored middleware that can be integrated independently into the base server. |
| [client.py](py-http-server-main/client.py) | Normal authentication client and shared HTTP transport. |
| [client_subverted.py](py-http-server-main/client_subverted.py) | Client with normal authentication by default and an explicit `--backdoor` demonstration. |
| [tests/](py-http-server-main/tests/) | Automated tests. |
| [PART1_运行说明.md](py-http-server-main/PART1_运行说明.md) | Detailed protocol, environment, and verification notes in Chinese. |
| [Base server README](py-http-server-main/README.md) | Original server routing and middleware documentation. |

The coursework report and final submission ZIP have not been generated. This repository is for development and execution; prepare the final submission separately according to the coursework requirements.
