from web3 import Web3
from eth_account import Account as eact
import didkit
import json
import asyncio

async def main():
    aurl = "https://eth-sepolia.g.alchemy.com/v2/oo8-01ZhEVkueEsF708nB"
    w3 = Web3(Web3.HTTPProvider(aurl))
    print(w3.is_connected())

    holder_key = didkit.generate_ed25519_key()
    holder_did = didkit.key_to_did("key", holder_key)

    print("Holder_Key: ",holder_key)
    print("Holder_did: ",holder_did)

    acnt= eact.create()
    issuer_did=f"did:eth:sepolia:{acnt.address}"
    print("Issuer_did: ",issuer_did)


    vc = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "IDCard"],
    "issuer": issuer_did,
    "issuanceDate": "2025-11-13T00:00:00Z",
    "credentialSubject": {
        "id": holder_did,
        "name": "Tester",
        "age": 321
    }
    }
    vc_jwt = didkit.issue_credential(json.dumps(vc),"{}",holder_key)
    print(vc_jwt)
    
asyncio.run(main())
