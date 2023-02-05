# Implementation inspired by https://github.com/karmacoma-eth/smol-evm
# Implementation inspired by https://github.com/jaglinux/evm-from-scratch
# all opcodes implemented

import json
import os
import sha3
import copy
from lib import Account, WorldState, Context, OpcodeResponse, OpcodeData
from lib import unsigned_to_signed, signed_to_unsigned
from lib import UINT256MAX, STATICCALL_DISSALOWED_OPCODES


def opcodeStop(ctx, info):
    return OpcodeResponse(success=True, encounteredStop=True, data=None)


def opcodePush(ctx, info, numericPartOfName):
    data = 0
    for i in range(numericPartOfName):
        data = (data << 8) | ctx.code[ctx.pc + 1]
        ctx.pc += 1
    ctx.stack.push(data)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodePop(ctx, info):
    data = ctx.stack.pop()
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeAdd(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    result = (a + b)
    # overflow condition
    result &= UINT256MAX
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeMul(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    result = (a * b)
    # overflow condition
    result &= UINT256MAX
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSub(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    result = (a - b)
    result &= UINT256MAX
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeDiv(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    # Handle Divide by 0
    if b == 0:
        result = 0
    else:
        result = int(a / b)
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeMod(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    if b == 0:
        result = 0
    else:
        result = a % b
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeAddMod(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    result = a + b
    c = ctx.stack.pop()
    result = result % c
    result &= UINT256MAX
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeMulMod(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    result = a * b
    c = ctx.stack.pop()
    result = result % c
    result &= UINT256MAX
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeExp(ctx, info):
    a = ctx.stack.pop()
    exponent = ctx.stack.pop()
    result = a ** exponent
    result &= UINT256MAX
    ctx.stack.push(result)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSignExtend(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    b = b & ((1 << (a + 1) * 8) - 1)
    if (b >> ((a + 1) * 8 - 1)) != 0:
        mask = UINT256MAX ^ ((1 << (a + 1) * 8) - 1)
        b = b | mask
    ctx.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSDiv(ctx, info):
    a = unsigned_to_signed(ctx.stack.pop())
    b = unsigned_to_signed(ctx.stack.pop())
    ctx.stack.push(signed_to_unsigned(a // b) if b != 0 else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSMod(ctx, info):
    a = unsigned_to_signed(ctx.stack.pop())
    b = unsigned_to_signed(ctx.stack.pop())
    ctx.stack.push(signed_to_unsigned(a % b) if b != 0 else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeLT(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if a < b else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeGT(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(1 if a > b else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSLT(ctx, info):
    a = unsigned_to_signed(ctx.stack.pop())
    b = unsigned_to_signed(ctx.stack.pop())
    ctx.stack.push(1 if a < b else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSGT(ctx, info):
    a = unsigned_to_signed(ctx.stack.pop())
    b = unsigned_to_signed(ctx.stack.pop())
    ctx.stack.push(1 if a > b else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeEQ(ctx, info):
    ctx.stack.push(1 if ctx.stack.pop() == ctx.stack.pop() else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeIsZero(ctx, info):
    ctx.stack.push(1 if ctx.stack.pop() == 0 else 0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeAnd(ctx, info):
    ctx.stack.push((ctx.stack.pop() & ctx.stack.pop()))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeOR(ctx, info):
    ctx.stack.push((ctx.stack.pop() | ctx.stack.pop()))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeXOR(ctx, info):
    ctx.stack.push((ctx.stack.pop() ^ ctx.stack.pop()))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeNot(ctx, info):
    ctx.stack.push(UINT256MAX ^ ctx.stack.pop())
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSHL(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(0 if a >= 256 else ((b << a) % 2 ** 256))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSHR(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.stack.push(b >> a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSAR(ctx, info):
    shift, signed_value = ctx.stack.pop(), unsigned_to_signed(ctx.stack.pop())
    ctx.stack.push(signed_to_unsigned(signed_value >> shift))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeByte(ctx, info):
    offset, value = ctx.stack.pop(), ctx.stack.pop()
    if offset < 32:
        ctx.stack.push((value >> ((31 - offset) * 8)) & 0xFF)
    else:
        ctx.stack.push(0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeDup(ctx, info, numericPartOfName):
    a = ctx.stack.access_at_index(numericPartOfName * -1)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSwap(ctx, info, numericPartOfName):
    a = ctx.stack.access_at_index((numericPartOfName + 1) * -1)
    b = ctx.stack.pop()
    ctx.stack.push(a)
    ctx.stack.set_at_index((numericPartOfName + 1) * -1, b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeInvalid(ctx, info):
    return OpcodeResponse(success=False, encounteredStop=False, data=None)


def opcodePC(ctx, info):
    ctx.stack.push(ctx.pc)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeGas(ctx, info):
    ctx.stack.push(UINT256MAX)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeJump(ctx, info):
    a = ctx.stack.pop()
    if a in ctx.valid_jumpdests_set:
        ctx.set_pc(a)
        return OpcodeResponse(success=True, encounteredStop=False, data=None)
    else:
        return OpcodeResponse(success=False, encounteredStop=False, data=None)


def opcodeJumpIf(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    if b == 0:
        return OpcodeResponse(success=True, encounteredStop=False, data=None)
    else:
        if a in ctx.valid_jumpdests_set:
            ctx.set_pc(a)
            return OpcodeResponse(
                success=True, encounteredStop=False, data=None)
        else:
            return OpcodeResponse(
                success=False,
                encounteredStop=False,
                data=None)


def opcodeJumpDest(ctx, info):
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeMLoad(ctx, info):
    a = ctx.stack.pop()
    b = int(ctx.memory.load(a, 32).hex(), 16)
    ctx.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeMStore(ctx, info):
    a = ctx.stack.pop()
    b = hex(ctx.stack.pop())[2:]
    if len(b) % 2 == 1:
        b = "0" + b
    b = bytes.fromhex(b)

    size = len(b)
    b = bytes(32 - size) + b

    ctx.memory.store(a, b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeMStore8(ctx, info):
    a = ctx.stack.pop()
    b = hex(ctx.stack.pop())[2:]
    if len(b) % 2 == 1:
        b = "0" + b
    b = bytes.fromhex(b)

    size = len(b)

    if size == 1:
        ctx.memory.store(a, b)
        return OpcodeResponse(success=True, encounteredStop=False, data=None)
    else:
        return OpcodeResponse(success=False, encounteredStop=False, data=None)


def opcodeMSize(ctx, info):
    ctx.stack.push(ctx.memory.msize())
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSHA3(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.memory.load(a, b)
    ctx.stack.push(int(sha3.keccak_256(bytes(c)).digest().hex(), 16))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeAddress(ctx, info):
    a = int(info["tx"]["to"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCaller(ctx, info):
    a = int(info["tx"]["from"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeOrigin(ctx, info):
    a = int(info["tx"]["origin"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeGasPrice(ctx, info):
    a = int(info["tx"]["gasprice"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeBaseFee(ctx, info):
    a = int(info["block"]["basefee"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCoinBase(ctx, info):
    a = int(info["block"]["coinbase"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeTimeStamp(ctx, info):
    a = int(info["block"]["timestamp"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeNumber(ctx, info):
    a = int(info["block"]["number"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeDifficulty(ctx, info):
    a = int(info["block"]["difficulty"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeGasLimit(ctx, info):
    a = int(info["block"]["gaslimit"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeChainId(ctx, info):
    a = int(info["block"]["chainid"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeBlockHash(ctx, info):
    ctx.stack.push(0x0)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeBalance(ctx, info):
    a = ctx.stack.pop()
    if not ctx.world_state.get(a):
        ctx.stack.push(0)
    else:

        b = ctx.world_state.get(a).getBalance()
        ctx.stack.push(b)

    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCallValue(ctx, info):
    a = int(info["tx"]["value"], 16)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCallDataLoad(ctx, info):
    a = ctx.stack.pop()
    b = int(ctx.calldata.load(a, 32).hex(), 16)
    ctx.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCallDataSize(ctx, info):
    a = ctx.calldata.size()
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCallDataCopy(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.stack.pop()
    calldata = ctx.calldata.load(b, c)
    ctx.memory.store(a, calldata)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCodeSize(ctx, info):
    a = len(ctx.code)
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCodeCopy(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.stack.pop()
    size = len(ctx.code)
    code = bytearray(ctx.code)
    if b + c > size:
        code.extend(bytes((b + c) - size))

    ctx.memory.store(a, code[b:b + c])
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeExtCodeSize(ctx, info):
    a = ctx.stack.pop()
    if not ctx.world_state.get(a):
        ctx.stack.push(0)
    else:
        ctx.stack.push(len(ctx.world_state.get(a).code))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeExtCodeCopy(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.stack.pop()
    d = ctx.stack.pop()
    if not ctx.world_state.get(a):
        ctx.memory.store(b, bytes())
    else:
        size = len(ctx.world_state.get(a).code)
        code = bytearray(ctx.world_state.get(a).code)
        if c + d > size:
            code.extend(bytes((c + d) - size))
        ctx.memory.store(b, code[c:c + d])
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeExtCodeHash(ctx, info):
    a = ctx.stack.pop()
    if not ctx.world_state.get(a):
        ctx.stack.push(0)
    else:
        code = bytearray(ctx.world_state.get(a).code)
        ctx.stack.push(int(sha3.keccak_256(bytes(code)).digest().hex(), 16))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSelfBalance(ctx, info):
    a = int(info["tx"]["to"], 16)
    if not ctx.world_state.get(a):
        ctx.stack.push(0)
    else:
        b = ctx.world_state.get(a).getBalance()
        ctx.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSStore(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    ctx.storage.store(a, b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSLoad(ctx, info):
    a = ctx.stack.pop()
    b = ctx.storage.load(a)
    ctx.stack.push(b)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeLog(ctx, info, numericPartOfName):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = int(ctx.memory.load(a, b).hex(), 16)
    log = {}
    log["address"] = int(info["tx"]["to"], 16)
    log["data"] = c
    log["topics"] = []
    for i in range(numericPartOfName):
        log["topics"].append(ctx.stack.pop())
    ctx.logs.append(log)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeReturn(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = int(ctx.memory.load(a, b).hex(), 16)
    return OpcodeResponse(success=True, encounteredStop=False, data=c)


def opcodeRevert(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = int(ctx.memory.load(a, b).hex(), 16)
    return OpcodeResponse(success=False, encounteredStop=False, data=c)


def opcodeCall(ctx, info):
    gas = ctx.stack.pop()
    address = ctx.stack.pop()
    value = ctx.stack.pop()
    if info["isStaticCall"] and value != 0:
        return OpcodeResponse(success=False, encounteredStop=False, data=None)
    argOffset = ctx.stack.pop()
    argSize = ctx.stack.pop()
    retOffset = ctx.stack.pop()
    retSize = ctx.stack.pop()
    new_info = copy.deepcopy(info)

    if info.get("tx") and info.get("tx").get("to"):
        new_info["tx"]["from"] = str(info["tx"]["to"])
    if new_info.get("tx"):
        new_info["tx"]["to"] = hex(address)[2:]
    else:
        new_info["tx"] = {"to": hex(address)[2:]}

    code = ctx.world_state.get(address).code
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code, new_info, 0, False)

    if success:
        ctx.world_state = after_execution_world_state

    if returndata:
        returndata = hex(returndata)[2:]
        if len(returndata) % 2 == 1:
            returndata = "0" + returndata

        returndata = returndata[:retSize * 2]
        returndata = bytearray.fromhex(returndata)

        ctx.returndata.setreturndata(returndata)
        ctx.memory.store(retOffset, returndata)
    ctx.stack.push(int(success))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeReturnDataSize(ctx, info):
    a = ctx.returndata.size()
    ctx.stack.push(a)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeReturnDataCopy(ctx, info):
    a = ctx.stack.pop()
    b = ctx.stack.pop()
    c = ctx.stack.pop()
    returndata = ctx.returndata.load(b, c)
    ctx.memory.store(a, returndata)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeDelegateCall(ctx, info):
    gas = ctx.stack.pop()
    address = ctx.stack.pop()
    argOffset = ctx.stack.pop()
    argSize = ctx.stack.pop()
    retOffset = ctx.stack.pop()
    retSize = ctx.stack.pop()
    new_info = copy.deepcopy(info)

    code = ctx.world_state.get(address).code
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code, new_info, 0, False)

    if success:
        ctx.world_state = after_execution_world_state

    if returndata:
        returndata = hex(returndata)[2:]
        if len(returndata) % 2 == 1:
            returndata = "0" + returndata

        returndata = returndata[:retSize * 2]
        returndata = bytearray.fromhex(returndata)

        ctx.returndata.setreturndata(returndata)
        ctx.memory.store(retOffset, returndata)
    ctx.stack.push(int(success))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeStaticCall(ctx, info):
    gas = ctx.stack.pop()
    address = ctx.stack.pop()
    argOffset = ctx.stack.pop()
    argSize = ctx.stack.pop()
    retOffset = ctx.stack.pop()
    retSize = ctx.stack.pop()
    new_info = copy.deepcopy(info)

    if info.get("tx") and info.get("tx").get("to"):
        new_info["tx"]["from"] = str(info["tx"]["to"])
    if new_info.get("tx"):
        new_info["tx"]["to"] = hex(address)[2:]
    else:
        new_info["tx"] = {"to": hex(address)[2:]}

    code = ctx.world_state.get(address).code
    (success, stack, logs, returndata, after_execution_world_state) = evm(
        code, new_info, 0, True)

    if success:
        ctx.world_state = after_execution_world_state
    if returndata:
        returndata = hex(returndata)[2:]
        if len(returndata) % 2 == 1:
            returndata = "0" + returndata

        returndata = returndata[:retSize * 2]
        returndata = bytearray.fromhex(returndata)

        ctx.returndata.setreturndata(returndata)
        ctx.memory.store(retOffset, returndata)
    ctx.stack.push(int(success))
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeCreate(ctx, info):
    value = ctx.stack.pop()
    offset = ctx.stack.pop()
    size = ctx.stack.pop()

    current_address = info["tx"]["to"][2:]
    if ctx.world_state.get(current_address):
        nonce = ctx.world_state.get(current_address).nonce
    else:
        nonce = 0
    current_address = bytes.fromhex(current_address)

    nonce = hex(nonce)[2:]
    if len(nonce) % 2 == 1:
        nonce = "0" + nonce
    nonce = bytes.fromhex(nonce)
    contract_address = int(
        sha3.keccak_256(
            bytes(
                current_address +
                nonce)).digest().hex(),
        16)

    code = ctx.memory.load(offset, size)
    (success, stack, logs, returndata,
     after_execution_world_state) = evm(code, info, 0, False)

    if not success:
        ctx.stack.push(0)
        return OpcodeResponse(success=True, encounteredStop=False, data=None)

    if not returndata:
        returndata = bytes()
    else:
        returndata = bytes.fromhex(hex(returndata)[2:])

    ctx.world_state.set(
        contract_address,
        Account(
            balance=value,
            code=returndata))
    ctx.stack.push(contract_address)
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


def opcodeSelfDestruct(ctx, info):
    a = ctx.stack.pop()
    current_address = int(info["tx"]["to"], 16)

    if ctx.world_state.get(a):
        ctx.world_state.get(
            a).balance += ctx.world_state.get(current_address).balance
    else:
        ctx.world_state.set(
            a, Account(
                balance=ctx.world_state.get(current_address).balance))

    ctx.world_state.get(current_address).balance = 0
    ctx.world_state.get(current_address).code = bytes()
    return OpcodeResponse(success=True, encounteredStop=False, data=None)


opcode = {}
opcode[0x00] = OpcodeData(0x00, "STOP", opcodeStop)
opcode[0x60] = OpcodeData(0x60, "PUSH1", opcodePush, 1)
opcode[0x61] = OpcodeData(0x61, "PUSH2", opcodePush, 2)
opcode[0x62] = OpcodeData(0x62, "PUSH3", opcodePush, 3)
opcode[0x63] = OpcodeData(0x63, "PUSH4", opcodePush, 4)
opcode[0x64] = OpcodeData(0x64, "PUSH5", opcodePush, 5)
opcode[0x65] = OpcodeData(0x65, "PUSH6", opcodePush, 6)
opcode[0x66] = OpcodeData(0x66, "PUSH7", opcodePush, 7)
opcode[0x67] = OpcodeData(0x67, "PUSH8", opcodePush, 8)
opcode[0x68] = OpcodeData(0x68, "PUSH9", opcodePush, 9)
opcode[0x69] = OpcodeData(0x69, "PUSH10", opcodePush, 10)
opcode[0x6A] = OpcodeData(0x6A, "PUSH11", opcodePush, 11)
opcode[0x6B] = OpcodeData(0x6B, "PUSH12", opcodePush, 12)
opcode[0x6C] = OpcodeData(0x6C, "PUSH13", opcodePush, 13)
opcode[0x6D] = OpcodeData(0x6D, "PUSH14", opcodePush, 14)
opcode[0x6E] = OpcodeData(0x6E, "PUSH15", opcodePush, 15)
opcode[0x6F] = OpcodeData(0x6F, "PUSH16", opcodePush, 16)
opcode[0x70] = OpcodeData(0x70, "PUSH17", opcodePush, 17)
opcode[0x71] = OpcodeData(0x71, "PUSH18", opcodePush, 18)
opcode[0x72] = OpcodeData(0x72, "PUSH19", opcodePush, 19)
opcode[0x73] = OpcodeData(0x73, "PUSH20", opcodePush, 20)
opcode[0x74] = OpcodeData(0x74, "PUSH21", opcodePush, 21)
opcode[0x75] = OpcodeData(0x75, "PUSH22", opcodePush, 22)
opcode[0x76] = OpcodeData(0x76, "PUSH23", opcodePush, 23)
opcode[0x77] = OpcodeData(0x77, "PUSH24", opcodePush, 24)
opcode[0x78] = OpcodeData(0x78, "PUSH25", opcodePush, 25)
opcode[0x79] = OpcodeData(0x79, "PUSH26", opcodePush, 26)
opcode[0x7A] = OpcodeData(0x7A, "PUSH27", opcodePush, 27)
opcode[0x7B] = OpcodeData(0x7B, "PUSH28", opcodePush, 28)
opcode[0x7C] = OpcodeData(0x7C, "PUSH29", opcodePush, 29)
opcode[0x7D] = OpcodeData(0x7D, "PUSH30", opcodePush, 30)
opcode[0x7E] = OpcodeData(0x7E, "PUSH31", opcodePush, 31)
opcode[0x7F] = OpcodeData(0x7F, "PUSH32", opcodePush, 32)
opcode[0x50] = OpcodeData(0x50, "POP", opcodePop)
opcode[0x01] = OpcodeData(0x01, "ADD", opcodeAdd)
opcode[0x02] = OpcodeData(0x02, "MUL", opcodeMul)
opcode[0x03] = OpcodeData(0x03, "SUB", opcodeSub)
opcode[0x04] = OpcodeData(0x04, "DIV", opcodeDiv)
opcode[0x06] = OpcodeData(0x06, "MOD", opcodeMod)
opcode[0x08] = OpcodeData(0x08, "MODADD", opcodeAddMod)
opcode[0x09] = OpcodeData(0x09, "MODMUL", opcodeMulMod)
opcode[0x0a] = OpcodeData(0xa, "EXP", opcodeExp)
opcode[0x0b] = OpcodeData(0xa, "SIGNEXTEND", opcodeSignExtend)
opcode[0x05] = OpcodeData(0x5, "SDIV", opcodeSDiv)
opcode[0x07] = OpcodeData(0x7, "SMOD", opcodeSMod)
opcode[0x10] = OpcodeData(0x10, "LT", opcodeLT)
opcode[0x11] = OpcodeData(0x11, "GT", opcodeGT)
opcode[0x12] = OpcodeData(0x12, "SLT", opcodeSLT)
opcode[0x13] = OpcodeData(0x13, "SGT", opcodeSGT)
opcode[0x14] = OpcodeData(0x14, "EQ", opcodeEQ)
opcode[0x15] = OpcodeData(0x15, "ISZERO", opcodeIsZero)
opcode[0x16] = OpcodeData(0x16, "AND", opcodeAnd)
opcode[0x17] = OpcodeData(0x17, "OR", opcodeOR)
opcode[0x18] = OpcodeData(0x18, "XOR", opcodeXOR)
opcode[0x19] = OpcodeData(0x19, "NOT", opcodeNot)
opcode[0x1b] = OpcodeData(0x1b, "SHL", opcodeSHL)
opcode[0x1c] = OpcodeData(0x1c, "SHR", opcodeSHR)
opcode[0x1d] = OpcodeData(0x1d, "SAR", opcodeSAR)
opcode[0x1a] = OpcodeData(0x1a, "BYTE", opcodeByte)
opcode[0x80] = OpcodeData(0x80, "DUP1", opcodeDup, 1)
opcode[0x81] = OpcodeData(0x81, "DUP2", opcodeDup, 2)
opcode[0x82] = OpcodeData(0x82, "DUP3", opcodeDup, 3)
opcode[0x83] = OpcodeData(0x83, "DUP4", opcodeDup, 4)
opcode[0x84] = OpcodeData(0x84, "DUP5", opcodeDup, 5)
opcode[0x85] = OpcodeData(0x85, "DUP6", opcodeDup, 6)
opcode[0x86] = OpcodeData(0x86, "DUP7", opcodeDup, 7)
opcode[0x87] = OpcodeData(0x87, "DUP8", opcodeDup, 8)
opcode[0x88] = OpcodeData(0x88, "DUP9", opcodeDup, 9)
opcode[0x89] = OpcodeData(0x89, "DUP10", opcodeDup, 10)
opcode[0x8A] = OpcodeData(0x8A, "DUP11", opcodeDup, 11)
opcode[0x8B] = OpcodeData(0x8B, "DUP12", opcodeDup, 12)
opcode[0x8C] = OpcodeData(0x8C, "DUP13", opcodeDup, 13)
opcode[0x8D] = OpcodeData(0x8D, "DUP14", opcodeDup, 14)
opcode[0x8E] = OpcodeData(0x8E, "DUP15", opcodeDup, 15)
opcode[0x8F] = OpcodeData(0x8F, "DUP16", opcodeDup, 16)
opcode[0x90] = OpcodeData(0x90, "SWAP1", opcodeSwap, 1)
opcode[0x91] = OpcodeData(0x91, "SWAP2", opcodeSwap, 2)
opcode[0x92] = OpcodeData(0x92, "SWAP3", opcodeSwap, 3)
opcode[0x93] = OpcodeData(0x93, "SWAP4", opcodeSwap, 4)
opcode[0x94] = OpcodeData(0x94, "SWAP5", opcodeSwap, 5)
opcode[0x95] = OpcodeData(0x95, "SWAP6", opcodeSwap, 6)
opcode[0x96] = OpcodeData(0x96, "SWAP7", opcodeSwap, 7)
opcode[0x97] = OpcodeData(0x97, "SWAP8", opcodeSwap, 8)
opcode[0x98] = OpcodeData(0x98, "SWAP9", opcodeSwap, 9)
opcode[0x99] = OpcodeData(0x99, "SWAP10", opcodeSwap, 10)
opcode[0x9A] = OpcodeData(0x9A, "SWAP11", opcodeSwap, 11)
opcode[0x9B] = OpcodeData(0x9B, "SWAP12", opcodeSwap, 12)
opcode[0x9C] = OpcodeData(0x9C, "SWAP13", opcodeSwap, 13)
opcode[0x9D] = OpcodeData(0x9D, "SWAP14", opcodeSwap, 14)
opcode[0x9E] = OpcodeData(0x9E, "SWAP15", opcodeSwap, 15)
opcode[0x9F] = OpcodeData(0x9F, "SWAP16", opcodeSwap, 16)
opcode[0xfe] = OpcodeData(0xfe, "INVALID", opcodeInvalid)
opcode[0x58] = OpcodeData(0x58, "PC", opcodePC)
opcode[0x5a] = OpcodeData(0x5a, "GAS", opcodeGas)
opcode[0x56] = OpcodeData(0x56, "JUMP", opcodeJump)
opcode[0x57] = OpcodeData(0x57, "JUMPI", opcodeJumpIf)
opcode[0x5b] = OpcodeData(0x57, "JUMPDEST", opcodeJumpDest)
opcode[0x51] = OpcodeData(0x51, "MLOAD", opcodeMLoad)
opcode[0x52] = OpcodeData(0x52, "MSTORE", opcodeMStore)
opcode[0x53] = OpcodeData(0x53, "MSTORE8", opcodeMStore8)
opcode[0x59] = OpcodeData(0x59, "MSIZE", opcodeMSize)
opcode[0x20] = OpcodeData(0x20, "SHA3", opcodeSHA3)
opcode[0x30] = OpcodeData(0x30, "ADDRESS", opcodeAddress)
opcode[0x33] = OpcodeData(0x33, "CALLER", opcodeCaller)
opcode[0x32] = OpcodeData(0x32, "ORIGIN", opcodeOrigin)
opcode[0x3a] = OpcodeData(0x99, "GASPRICE", opcodeGasPrice)
opcode[0x48] = OpcodeData(0x48, "BASEFEE", opcodeBaseFee)
opcode[0x41] = OpcodeData(0x41, "COINBASE", opcodeCoinBase)
opcode[0x42] = OpcodeData(0x42, "TIMESTAMP", opcodeTimeStamp)
opcode[0x43] = OpcodeData(0x43, "NUMBER", opcodeNumber)
opcode[0x44] = OpcodeData(0x44, "DIFFICULTY", opcodeDifficulty)
opcode[0x45] = OpcodeData(0x45, "GASLIMIT", opcodeGasLimit)
opcode[0x46] = OpcodeData(0x46, "CHAINID", opcodeChainId)
opcode[0x40] = OpcodeData(0x40, "BLOCKHASH", opcodeBlockHash)
opcode[0x31] = OpcodeData(0x31, "BALANCE", opcodeBalance)
opcode[0x34] = OpcodeData(0x34, "CALLVALUE", opcodeCallValue)
opcode[0x35] = OpcodeData(0x35, "CALLDATALOAD", opcodeCallDataLoad)
opcode[0x36] = OpcodeData(0x36, "CALLDATASIZE", opcodeCallDataSize)
opcode[0x37] = OpcodeData(0x37, "CALLDATACOPY", opcodeCallDataCopy)
opcode[0x38] = OpcodeData(0x38, "CODESIZE", opcodeCodeSize)
opcode[0x39] = OpcodeData(0x39, "CODECOPY", opcodeCodeCopy)
opcode[0x3b] = OpcodeData(0x3b, "EXTCODESIZE", opcodeExtCodeSize)
opcode[0x3c] = OpcodeData(0x3c, "EXTCODECOPY", opcodeExtCodeCopy)
opcode[0x3f] = OpcodeData(0x3f, "EXTCODEHASH", opcodeExtCodeHash)
opcode[0x47] = OpcodeData(0x47, "SELFBALANCE", opcodeSelfBalance)
opcode[0x54] = OpcodeData(0x54, "SLOAD", opcodeSLoad)
opcode[0x55] = OpcodeData(0x55, "SSTORE", opcodeSStore)
opcode[0xa0] = OpcodeData(0xa0, "LOG0", opcodeLog, 0)
opcode[0xa1] = OpcodeData(0xa1, "LOG1", opcodeLog, 1)
opcode[0xa2] = OpcodeData(0xa2, "LOG2", opcodeLog, 2)
opcode[0xa3] = OpcodeData(0xa3, "LOG3", opcodeLog, 3)
opcode[0xa4] = OpcodeData(0xa4, "LOG4", opcodeLog, 4)
opcode[0xf3] = OpcodeData(0xf3, "RETURN", opcodeReturn)
opcode[0xfd] = OpcodeData(0xfd, "REVERT", opcodeRevert)
opcode[0xf1] = OpcodeData(0xf1, "CALL", opcodeCall)
opcode[0x3d] = OpcodeData(0x3d, "RETURNDATASIZE", opcodeReturnDataSize)
opcode[0x3e] = OpcodeData(0x3e, "RETURNDATACOPY", opcodeReturnDataCopy)
opcode[0xf4] = OpcodeData(0xf4, "DELEGATECALL", opcodeDelegateCall)
opcode[0xfa] = OpcodeData(0xfa, "STATICCALL", opcodeStaticCall)
opcode[0xf0] = OpcodeData(0xfa, "CREATE", opcodeCreate)
opcode[0xff] = OpcodeData(0xff, "SELFDESTRUCT", opcodeSelfDestruct)


def evm(code, info, outputStackLen, isStaticCall):

    opcodeReturn = OpcodeResponse(True, False, None)
    info["isStaticCall"] = False
    account_states = dict()

    if info.get("state"):
        state_info = info.get("state")
        for address in state_info.keys():
            state_code = bytes()
            if state_info.get(address).get("code") and state_info.get(
                    address).get("code").get("bin"):
                state_code = bytes.fromhex(
                    state_info.get(address).get("code").get("bin"))
            account_tuple = Account(
                state_info.get(address).get("nonce"),
                state_info.get(address).get("balance"),
                state_info.get(address).get("storage"),
                state_code
            )
            account_states[int(address, 16)] = account_tuple

    world_state = WorldState(account_states)
    calldata = bytes()
    if info.get("tx") and info.get("tx").get("data"):
        calldata = bytes.fromhex(info.get("tx").get("data"))
    ctx = Context(world_state=world_state, code=code, calldata=calldata)

    while ctx.pc < len(code):
        op = code[ctx.pc]
        if isStaticCall:
            info["isStaticCall"] = False
            if op in STATICCALL_DISSALOWED_OPCODES:
                opcodeReturn.success = False
                break
        # pc will always increment by 1 here
        # pc can also be incremented in PUSH opcodes
        opcodeObj = opcode.get(op)
        if opcodeObj:
            print(
                f'\033[0;39mRunning opcode {hex(opcodeObj.opcode)} {opcodeObj.name}')

            if opcodeObj.numericPartOfName is None:
                opcodeReturn = opcodeObj.run(ctx, info)
            else:
                opcodeReturn = opcodeObj.run(
                    ctx, info, opcodeObj.numericPartOfName)
            if opcodeReturn.encounteredStop:
                break
            if not opcodeReturn.success:
                break
        else:
            print("Opcode implementation not found for ", hex(op))
            # return fake success but empty stack so that test case
            # panics with proper test name and error message
            return (True, [], [], None, WorldState())
        ctx.pc += 1

    result = []
    logs = ctx.logs
    returndata = opcodeReturn.data

    if not opcodeReturn.success:
        return (opcodeReturn.success, result, logs, returndata, world_state)

    if len(ctx.stack.list):
        if outputStackLen > 1:
            # output format is different if output stack is greater than 2
            # check evm.json for more details.
            while len(ctx.stack.list):
                result.append(ctx.stack.pop())
        else:
            tempList = [f'{i:x}' for i in ctx.stack.list]
            result.append(int(''.join(tempList), 16))
    return (opcodeReturn.success, result, logs, returndata, world_state)


def test():
    script_dirname = os.path.dirname(os.path.abspath(__file__))
    json_file = os.path.join(script_dirname, "..", "test", "tests.json")
    with open(json_file) as f:
        data = json.load(f)
        total = len(data)

        for i, test in enumerate(data):
            # Note: as the test cases get more complex, you'll need to modify this
            # to pass down more arguments to the evm function
            code = bytes.fromhex(test['code']['bin'])
            info = test
            expected_stack = test['expect'].get('stack', [])
            expected_logs = test['expect'].get('logs', [])
            expected_return = test['expect'].get('return', None)

            (success, stack, logs, returndata, after_execution_world_state) = evm(
                code, info, len(expected_stack), False)

            expected_stack = [int(x, 16) for x in expected_stack]
            if len(expected_logs) > 0:
                for log in expected_logs:
                    log["address"] = int(log["address"], 16)
                    log["data"] = int(log["data"], 16)
                    log["topics"] = [int(x, 16) for x in log["topics"]] if len(
                        log["topics"]) > 0 else []

            if expected_return:
                expected_return = int(expected_return, 16)

            if stack != expected_stack or success != test['expect'][
                    'success'] or logs != expected_logs or returndata != expected_return:
                print(f"❌ Test #{i + 1}/{total} {test['name']}")
                if stack != expected_stack:
                    print("Stack doesn't match")
                    print(" expected:", expected_stack)
                    print("   actual:", stack)
                if logs != expected_logs:
                    print("Logs don't match")
                    print(" expected: " + str(expected_logs))
                    print("   actual: " + str(logs))

                if success != test['expect']['success']:
                    print("Success doesn't match")
                    print(" expected:", test['expect']['success'])
                    print("   actual:", success)

                if returndata != expected_return:
                    print("Returndata doesn't match")
                    print(" expected:", expected_return)
                    print("   actual:", returndata)

                print("")
                print("Test code:")
                print(test['code']['asm'])
                print("")
                print("Hint:", test['hint'])
                print("")
                print(f"Progress: {i}/{len(data)}")
                print("")
                break
            else:
                print(f"\033[1;32m✓  Test #{i + 1}/{total} {test['name']}")
                print("")


if __name__ == '__main__':
    test()