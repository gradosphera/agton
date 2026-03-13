from __future__ import annotations

from agton.ton import Address, Cell, Builder, Slice, TlbConstructor
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class JettonNotify(TlbConstructor):
    '''
    transfer_notification#7362d09c query_id:uint64 amount:(VarUInteger 16)
           sender:MsgAddress forward_payload:(Either Cell ^Cell)
           = InternalMsgBody;
    '''
    query_id: int
    amount: int
    sender: Address
    forward_payload: Cell

    @classmethod
    def tag(cls):
        return 0x7362d09c, 32

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_uint(self.query_id, 64)
        b.store_coins(self.amount)
        b.store_address(self.sender)
        b.store_maybe_ref(self.forward_payload)
        return b

    @classmethod
    def deserialize_fields(cls, s: Slice) -> JettonNotify:
        query_id = s.load_uint(64)
        amount = s.load_coins()
        sender = s.load_address()
        forward_payload_in_ref = s.load_bool()
        if forward_payload_in_ref:
            forward_payload = s.load_ref()
        else:
            forward_payload = s.load_cell()
        return cls(query_id, amount, sender, forward_payload)
