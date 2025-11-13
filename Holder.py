import didkit

holder_key = didkit.generate_ed25519_key()
holder_did = didkit.key_to_did("key", holder_key)
print(holder_key)
print(holder_did)