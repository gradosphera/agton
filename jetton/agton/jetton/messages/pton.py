from __future__ import annotations
from typing import Self

from agton.ton import MsgAddress, Address, Cell, Builder, Slice, TlbConstructor
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class PtonTransfer(TlbConstructor):
    '''
    ton_transfer#01f3835d
        query_id:        uint64 
        ton_amount:      coins 
        refund_address:  MsgAddress 
        forward_payload: (Either Cell ^Cell) 
    = InternalMsgBody;
    '''
    query_id: int
    ton_amount: int
    refund_address: Address
    forwardPayload: Cell

    @classmethod
    def tag(cls):
        return 0x01f3835d, 32

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        query_id = s.load_uint(64)
        ton_amount = s.load_coins()
        refund_address = s.load_address()
        in_ref = s.load_bit()
        forward_payload = s.load_ref() if in_ref else s.load_cell()
        return cls(query_id, ton_amount, refund_address, forward_payload)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.query_id, 64)
        b.store_coins(self.ton_amount)
        b.store_address(self.refund_address)
        b.store_maybe_ref(self.forwardPayload)
        return b

