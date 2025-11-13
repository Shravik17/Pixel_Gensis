from web3 import Web3
aurl = "https://eth-sepolia.g.alchemy.com/v2/oo8-01ZhEVkueEsF708nB"
w3 = Web3(Web3.HTTPProvider(aurl))
print(w3.is_connected())