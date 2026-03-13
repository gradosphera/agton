from dataclasses import dataclass
from typing import Self

from ..cell import Builder, Slice

from .tlb import TlbConstructor
from .msg_address import MsgAddressInt
from .storage_info import StorageInfo
from .account_storage import AccountStorage

@dataclass(frozen=True, slots=True)
class AccountNone(TlbConstructor):
    '''account_none$0 = Account;'''

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b0, 1

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        return cls()

    def serialize_fields(self, b: Builder) -> Builder:
        return b

@dataclass(frozen=True, slots=True)
class AccountOrdinary(TlbConstructor):
    '''
    account$1 addr:MsgAddressInt storage_stat:StorageInfo
          storage:AccountStorage = Account;
    '''
    addr: MsgAddressInt
    storage_stat: StorageInfo
    storage: AccountStorage

    @classmethod
    def tag(cls) -> tuple[int, int]:
        return 0b1, 1

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        addr = s.load_msg_address_int()
        storage_stat = s.load_tlb(StorageInfo)
        storage = s.load_tlb(AccountStorage)
        return cls(addr, storage_stat, storage)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_msg_address_int(self.addr)
        b.store_tlb(self.storage_stat)
        b.store_tlb(self.storage)
        return b

Account = AccountOrdinary | AccountNone

def account(s: Slice) -> Account:
    match s.preload_bit():
        case 0: return AccountNone.deserialize(s)
        case 1: return AccountOrdinary.deserialize(s)
