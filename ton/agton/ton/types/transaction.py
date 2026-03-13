from dataclasses import dataclass, field
from typing import Self

from ..cell import Slice, Builder
from .tlb import TlbConstructor
from .account_status import AccountStatus, account_status
from .message import Message
from .currency_collection import CurrencyCollection
from .hash_update import HashUpdate
from .transaction_descr import TransactionDescr, transaction_descr
from .hashmap import Hashmap, HashmapCodec

OUT_MSGS_CODEC = (
    HashmapCodec()
    .with_uint_keys(15)
    .with_tlb_values(Message)
    .with_values_in_ref()
)

@dataclass(frozen=True, slots=True)
class Transaction(TlbConstructor):
    '''
    transaction$0111 account_addr:bits256 lt:uint64 
        prev_trans_hash:bits256 prev_trans_lt:uint64 now:uint32
        outmsg_cnt:uint15
        orig_status:AccountStatus end_status:AccountStatus
        ^[ in_msg:(Maybe ^(Message Any)) out_msgs:(HashmapE 15 ^(Message Any)) ]
        total_fees:CurrencyCollection state_update:^(HASH_UPDATE Account)
        description:^TransactionDescr = Transaction;
    '''
    account_addr: bytes
    lt: int
    prev_trans_hash: bytes = field(repr=False)
    prev_trans_lt: int
    now: int
    outmsg_cnt: int
    orig_status: AccountStatus
    end_status: AccountStatus
    in_msg: Message | None
    out_msgs: tuple[Message, ...]
    total_fees: CurrencyCollection
    state_update: HashUpdate
    description: TransactionDescr

    @classmethod
    def tag(cls) -> tuple[int, int] | None:
        return 0b0111, 4

    @classmethod
    def deserialize_fields(cls, s: Slice) -> Self:
        account_addr = s.load_bytes(32)
        lt = s.load_uint(64)
        prev_trans_hash = s.load_bytes(32)
        prev_trans_lt = s.load_uint(64)
        now = s.load_uint(32)
        outmsg_cnt = s.load_uint(15)
        orig_status = s.load_tlb(account_status)
        end_status = s.load_tlb(account_status)
        msg_slice = s.load_ref().begin_parse()
        in_msg = msg_slice.load_maybe_ref_tlb(Message)
        out_msgs: tuple[Message, ...]
        out_msgs_hashmap_e = msg_slice.load_hashmap_e(15)
        match out_msgs_hashmap_e:
            case None: out_msgs = tuple()
            case Hashmap() as hashmap:
                out_msgs_dict = OUT_MSGS_CODEC.decode(hashmap)
                out_msgs = tuple(out_msgs_dict[i] for i in range(outmsg_cnt))
        total_fees = s.load_tlb(CurrencyCollection)
        state_update = s.load_ref_tlb(HashUpdate)
        description = s.load_ref_tlb(transaction_descr)
        return cls(account_addr, lt, prev_trans_hash, prev_trans_lt,
                   now, outmsg_cnt, orig_status, end_status,
                   in_msg, out_msgs, total_fees, state_update, description)

    def serialize_fields(self, b: Builder) -> Builder:
        b.store_bytes(self.account_addr)
        b.store_uint(self.lt, 64)
        b.store_bytes(self.prev_trans_hash)
        b.store_uint(self.prev_trans_lt, 64)
        b.store_uint(self.now, 32)
        b.store_uint(self.outmsg_cnt, 15)
        b.store_tlb(self.orig_status)
        b.store_tlb(self.end_status)
        msgb = Builder()
        msgb.store_maybe_ref_tlb(self.in_msg)
        out_msgs = {i: m for i, m in enumerate(self.out_msgs)}
        msgb.store_hashmap_e(OUT_MSGS_CODEC.encode(out_msgs), 15)
        b.store_ref(msgb.end_cell())
        b.store_tlb(self.total_fees)
        b.store_ref_tlb(self.state_update)
        b.store_ref_tlb(self.description)
        return b
