"""Normal course Digest client with an explicit legacy-field demonstration.

The shared HTTP transport and normal calculations live in client.py.
This demonstration calculates its proof from the public challenge alone.
"""

import client


def build_backdoor_authorization(challenge, username, password, method, target):
    """Omit qop, nc and cnonce; the legacy verifier omits the password binding."""
    fields = client.challenge_fields(challenge)
    nonce = fields["nonce"]
    ha2 = client.hash_text(f"{method}:{target}")
    response = client.hash_text(f"{nonce}:{ha2}")
    values = [
        client.username_field(username),
        "realm=" + client.quote_value(fields["realm"]),
        "nonce=" + client.quote_value(nonce),
        "uri=" + client.quote_value(target),
        "algorithm=SHA-256",
        "response=" + client.quote_value(response),
    ]
    if "opaque" in fields:
        values.append("opaque=" + client.quote_value(fields["opaque"]))
    return "Digest " + ", ".join(values)


def main(argv=None):
    return client.main(argv, backdoor_builder=build_backdoor_authorization)


if __name__ == "__main__":
    raise SystemExit(main())
