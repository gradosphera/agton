from __future__ import annotations

from agton.ton import Address, Cell, Builder, Slice, TlbConstructor
from .transfer import JettonInternalTransfer
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class JettonMint(TlbConstructor):
    '''
    Unspecified by TEP-74, but widely used
    '''
    query_id: int
    recepient: Address
    value: int
    body: JettonInternalTransfer

    @classmethod
    def tag(cls):
        return 0x00000015, 32

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.query_id, 64)
        b.store_address(self.recepient)
        b.store_coins(self.value)
        b.store_ref_tlb(self.body)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> JettonMint:
        query_id = s.load_uint(64)
        recepient = s.load_address()
        value = s.load_coins()
        body = s.load_ref_tlb(JettonInternalTransfer)
        return cls(query_id, recepient, value, body)
