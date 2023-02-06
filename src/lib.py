from dataclasses import dataclass


#############
# CONSTANTS #
#############

UINT256MAX = (2 ** 256) - 1
# CREATE, CREATE2, LOG0, LOG1, LOG2, LOG3, LOG4, SSTORE, SELFDESTRUCT
# Check https://www.evm.codes/#fa for reference
STATICCALL_DISSALOWED_OPCODES = (
    0xa0,
    0xa1,
    0xa2,
    0xa3,
    0xa4,
    0xf0,
    0xf5,
    0x55,
    0xff)


########### 
# CLASSES #
###########

class WorldState:
    def __init__(self, initial_state=dict()):
        self.accounts = initial_state

    def get(self, address):
        return self.accounts.get(address)

    def set(self, address, account):
        self.accounts[address] = account


class Account:
    def __init__(self, nonce=0, balance=0, storage=None, code=bytes()):
        self.nonce = nonce
        self.balance = balance
        self.storage = storage if storage else Storage()
        self.code = code

    def getNonce(self):
        return int(self.nonce, 16)

    def getBalance(self):
        if isinstance(self.balance, int):
            return self.balance
        else:
            return int(self.balance, 16)

    def is_empty(self):
        return self.nonce == 0 and self.balance == 0 and self.code == b""


class Storage:
    def __init__(self, init=dict()):
        self.data = init

    def load(self, slot):
        return self.data.get(slot, 0)

    def store(self, slot, value):
        self.data[slot] = value


class Memory:
    def __init__(self):
        self.array = bytearray()

    def ceildiv(self, a, b):
        return -(a // -b)

    def msize(self):
        assert (len(self.array) % 32 == 0)
        return len(self.array)

    def expand_memory_if_required(self, offset, size):
        active_words = self.msize() // 32
        new_words = self.ceildiv((offset + size), 32)

        if new_words - active_words > 0:
            self.array.extend(bytes(32 * (new_words - active_words)))

    def store(self, offset, value):
        self.expand_memory_if_required(offset, len(value))
        self.array[offset:offset + len(value)] = value

    def load(self, offset, size):
        self.expand_memory_if_required(offset, size)
        a = bytearray()
        for i in range(offset, offset + size):
            b = hex(self.array[i])[2:]
            if len(b) % 2 == 1:
                b = "0" + b
            a += bytes.fromhex(b)
        return a


class Stack:
    def __init__(self, size=1024):
        self.list = []
        self.maxSize = size

    # Push max 32 bytes
    def push(self, item):
        if item > UINT256MAX:
            # TODO: handle error
            return False
        self.list.append(item)

    def pop(self):
        return self.list.pop()

    def access_at_index(self, index):
        return self.list[index]

    def set_at_index(self, index, item):
        self.list[index] = item


class Calldata:
    def __init__(self, data=bytes()) -> None:
        self.data = data

    def size(self):
        return len(self.data)

    def load(self, offset, size):
        a = bytearray()
        for i in range(offset, len(self.data)):
            b = hex(self.data[i])[2:]
            if len(b) % 2 == 1:
                b = "0" + b
            a += bytes.fromhex(b)

        if len(a) < size:
            a.extend(bytes(size - len(a)))
        return a


class Returndata:
    def __init__(self, data=bytes()) -> None:
        self.data = data

    def size(self):
        return len(self.data)

    def setreturndata(self, data):
        if data is None:
            self.data = bytes()
        else:
            self.data = data

    def load(self, offset, size):
        a = bytearray()
        for i in range(offset, len(self.data)):
            b = hex(self.data[i])[2:]
            if len(b) % 2 == 1:
                b = "0" + b
            a += bytes.fromhex(b)

        if len(a) < size:
            a.extend(bytes(size - len(a)))
        return a


class Context:
    def __init__(
        self,
        world_state=dict(),
        code=bytes(),
        pc=0,
        stack=None,
        calldata=None,
    ):

        self.world_state = world_state
        self.stack = stack if stack else Stack(1024)
        self.memory = Memory()
        self.code = code
        self.pc = pc
        self.valid_jumpdests_set = self.valid_jumpdests(code)
        self.calldata = Calldata(calldata)
        self.storage = Storage()
        self.logs = []
        self.returndata = Returndata()

    def set_pc(self, pc):
        self.pc = pc

    def valid_jumpdests(self, code):
        valid_dests = set()
        pc = 0
        while pc < len(code):
            op = code[pc]
            if op >= 0x60 and op < 0x70:
                pc += op - 0x60 + 1
            if pc < len(code) and op == 0x5b:
                valid_dests.add(pc)
            pc += 1

        return valid_dests


@dataclass
class OpcodeResponse:
    success: bool  # whether current execution completed successfully
    encounteredStop: bool  # stop will be True for stop opcode
    returnData: int  # pop, return etc. opcodes return data


class OpcodeData:
    def __init__(self, opcode, name, run, numericPartOfName=None):
        self.opcode = opcode
        self.name = name
        self.run = run  # function pointer
        # if opcode like push4 or dup2 or swap5
        self.numericPartOfName = numericPartOfName


#############
# FUNCTIONS #
#############

def unsigned_to_signed(n):
    if (n >> 255) != 0:
        return -(UINT256MAX + 1 - (n & UINT256MAX))
    return n & UINT256MAX


def signed_to_unsigned(n):
    if n < 0:
        n = UINT256MAX + n + 1
    return n & UINT256MAX
