# Part 1: Digest Authentication Backdoor Report

**Team name:** [Enter team name]  
**Team members:** [Enter all members' names]

## 1. Location and cause

The flaw is in `DigestAuthSubvertedMiddleware.__call__()` in `digest_auth_subverted.py`, lines 72–90, specifically `hashes[0] + COLON if modern else ""` on line 89. Omitting all three fields—`qop`, `nc` and `cnonce`—sets `modern` to false and selects the apparent legacy compatibility branch.

Normal authentication uses `HA1`, which incorporates the username, realm and stored password hash. The legacy branch skips `HA1` and its password binding in the final digest:

```text
response = H(nonce + ":" + H(method + ":" + uri))
```

Here, `H` returns the lowercase hexadecimal SHA-256 digest of UTF-8 text. Every input is available to the client. An attacker therefore needs a registered username, but neither its password nor its stored hash, to construct an accepted request.

## 2. Triggering the backdoor

1. From the server project directory, run `python3 start_server_subverted.py`. The password file must contain a registered account, and the requested file must exist.
2. In another terminal, run:

   ```bash
   python3 client_subverted.py --backdoor http://127.0.0.1:8080/README.md
   ```

3. Enter any registered username and any password. The client obtains a fresh nonce from the initial `401` challenge, computes the formula above, and sends the username, realm, nonce, URI, algorithm and response while omitting all three trigger fields.
4. The subverted server returns `200 OK` and the file contents. Unknown usernames remain rejected; the secure server rejects the same backdoor request with `401`. A fresh nonce is needed after each successful request. Omitting only some of the three fields does not activate the backdoor.

## 3. Why the flaw may be overlooked

The flaw sits within the digest calculation, without a hardcoded master password or special username. Normal logins work, and ordinary wrong passwords fail, so tests limited to that path may miss it. Checks for registered users, URI matching, nonce expiry, single use and digest equality remain in place.

The module describes support for modern and legacy parameters, and both paths share the digest calculation loop. A quick review may overlook that the legacy branch omits the password input. This does not make the flaw undetectable: tracing the final digest's inputs or testing requests without `qop` exposes it.

## 4. Protocol basis and alternatives

[RFC 7616 §3.4.2](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4.2) includes the password in A1; this project uses `SHA256(password)` as the Digest secret to accommodate the course password file. Even the older no-`qop` formula in [RFC 2617 §3.2.2.1](https://www.rfc-editor.org/rfc/rfc2617.html#section-3.2.2.1) retains `H(A1)`. Legacy compatibility therefore does not justify removing the password binding.

Two alternatives are a fixed master password and a special request header. The former leaves a conspicuous constant comparison; the latter introduces an extra trigger marker. The implemented approach instead changes the calculation through absent Digest fields, making it easier to mistake for compatibility handling. Its concealment still depends on whether reviewers examine that branch.
