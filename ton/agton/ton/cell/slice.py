from __future__ import annotations

from bitarray import frozenbitarray
from bitarray.util import ba2int
from typing import Self, Literal, Callable, cast, TYPE_CHECKING

from agton.ton.common.bitstring import BitString, int2bs


from .cell import Cell, OrdinaryCell
from .exceptions import CellOverflow, CellUnderflow

if TYPE_CHECKING:
    from ..types.tlb import TlbConstructor
    from ..types.msg_address import Address, MsgAddress, MsgAddressExt, MsgAddressInt
    from ..types.hashmap import Hashmap, HashmapE


class Slice:
    def __init__(self, c: Cell, ld: int, rd: int, lr: int, rr: int) -> None:
        self.c = c
        self.ld = ld
        self.rd = rd
        self.lr = lr
        self.rr = rr
        if not (ld <= rd <= len(c.data) and lr <= rr <= len(c.refs)):
            raise ValueError('Invalid cursors')
    
    def to_cell(self) -> OrdinaryCell:
        return OrdinaryCell(
            data=frozenbitarray(self.c.data[self.ld:self.rd]),
            refs=self.c.refs[self.lr:self.rr]
        )
    
    @property
    def remaining_bits(self) -> int:
        return self.rd - self.ld
    
    @property
    def remaining_refs(self) -> int:
        return self.rr - self.lr

    def _ensure_bits_cap(self, n: int) -> None:
        if n > self.remaining_bits:
            raise CellUnderflow(f'Tried to read {n} bits, when {self.remaining_bits} available')
    
    def _ensure_refs_cap(self, n: int) -> None:
        if n > self.remaining_refs:
            raise CellUnderflow(f'Tried to read {n} refs, when {self.remaining_refs} available')
    
    def end_parse(self) -> None:
        if not (self.lr == self.rr and self.ld == self.rd):
            raise CellOverflow('Expected no more data and refs, after .end_parse()')
    
    def with_skipped_bits(self, n: int) -> Slice:
        self._ensure_bits_cap(n)
        return Slice(self.c, self.ld + n, self.rd, self.lr, self.rr)
    
    def with_skipped_refs(self, n: int) -> Slice:
        self._ensure_refs_cap(n)
        return Slice(self.c, self.ld, self.rd, self.lr + n, self.rr)

    def preload_bits(self, n: int) -> BitString:
        self._ensure_bits_cap(n)
        return BitString(self.c.data[self.ld:self.ld + n])
    
    def load_bits(self, n: int) -> BitString:
        self._ensure_bits_cap(n)
        self.ld += n
        return BitString(self.c.data[self.ld - n:self.ld])
    
    def starts_with(self, p: BitString | tuple[int, int]) -> bool:
        if isinstance(p, tuple):
            p = int2bs(p[0], p[1])
        n = len(p)
        if n > self.remaining_bits:
            return False
        return self.preload_bits(n) == p

    def skip_bits(self, n: int) -> Self:
        self._ensure_bits_cap(n)
        self.ld += n
        return self

    def skip_prefix(self, p: BitString | tuple[int, int]) -> Self:
        if not self.starts_with(p):
            raise ValueError('Wrong prefix')
        n = p[1] if isinstance(p, tuple) else len(p)
        return self.skip_bits(n)

    def preload_ref(self) -> Cell:
        self._ensure_refs_cap(1)
        return self.c.refs[self.lr]
    
    def load_ref(self) -> Cell:
        self._ensure_refs_cap(1)
        self.lr += 1
        return self.c.refs[self.lr - 1]
    
    def preload_bytes(self, n: int) -> bytes:
        return self.preload_bits(n * 8).tobytes()
    
    def load_bytes(self, n: int) -> bytes:
        return self.load_bits(n * 8).tobytes()

    def load_uint(self, n: int) -> int:
        return ba2int(self.load_bits(n), signed=False)
    
    def preload_uint(self, n: int) -> int:
        return ba2int(self.preload_bits(n), signed=False)
    
    def load_int(self, n: int) -> int:
        return ba2int(self.load_bits(n), signed=True)
    
    def preload_int(self, n: int) -> int:
        return ba2int(self.preload_bits(n), signed=True)
    
    def load_bool(self) -> bool:
        return bool(self.load_uint(1))
    
    def preload_bool(self) -> bool:
        return bool(self.preload_uint(1))
    
    def load_bit(self) -> Literal[0, 1]:
        return 1 if self.load_bool() else 0
    
    def preload_bit(self) -> Literal[0, 1]:
        return 1 if self.preload_bool() else 0
    
    def preload_var_uint(self, n: int) -> int:
        bit_length = (n - 1).bit_length()
        length = self.preload_uint(bit_length)
        if not length:
            return 0
        return self.with_skipped_bits(bit_length).load_uint(length * 8)
    
    def load_var_uint(self, n: int) -> int:
        bit_length = (n - 1).bit_length()
        length = self.load_uint(bit_length)
        if not length:
            return 0
        return self.load_uint(length * 8)
    
    def preload_var_int(self, n: int) -> int:
        bit_length = (n - 1).bit_length()
        length = self.preload_uint(bit_length)
        if not length:
            return 0
        return self.with_skipped_bits(bit_length).load_int(length * 8)
    
    def load_var_int(self, n: int) -> int:
        bit_length = (n - 1).bit_length()
        length = self.load_uint(bit_length)
        if not length:
            return 0
        return self.load_int(length * 8)
    
    def load_coins(self) -> int:
        return self.load_var_uint(16)
    
    def preload_coins(self) -> int:
        return self.preload_var_uint(16)

    def load_maybe_ref(self) -> Cell | None:
        if self.load_bool():
            return self.load_ref()
        return None
    
    def load_snake_bytes(self) -> bytes:
        if self.remaining_bits % 8 != 0:
            raise ValueError(f'Invalid string length: {self.remaining_bits}')
        res = self.load_bytes(self.remaining_bits // 8)
        if self.remaining_refs:
            res += self.load_ref().begin_parse().load_snake_bytes()
        return res

    def load_snake_string(self) -> str:
        return self.load_snake_bytes().decode()
    
    def load_hashmap(self, n: int) -> Hashmap:
        from ..types.hashmap import load_hashmap
        return load_hashmap(self, n)
    
    def load_hashmap_e(self, n: int) -> HashmapE:
        c = self.load_maybe_ref()
        if c is None:
            return None
        return c.begin_parse().load_hashmap(n)
    
    # TlbTypeDeserializer = (
    #     type[TlbConstructor]
    #     | Callable[["Slice"], tuple[TlbConstructor, *tuple[Any, ...]]]
    #     | Callable[["Slice"], TlbConstructor]
    # )

    def load_tlb[T: TlbConstructor](self, deserializer: type[T] | Callable[[Slice], T]) -> T:
        if isinstance(deserializer, type):
            cls = cast(type[T], deserializer)
            return cls.deserialize(self)
        else:
            t = deserializer(self)
            return t
    
    def load_maybe_tlb[T: TlbConstructor](self, deserializer: type[T] | Callable[[Slice], T]) -> T | None:
        if self.load_bool():
            return self.load_tlb(deserializer)
        return None
    
    def load_ref_tlb[T: TlbConstructor](self, deserializer: type[T] | Callable[[Slice], T]) -> T:
        cs = self.load_ref().begin_parse()
        return cs.load_tlb(deserializer)
    
    def load_maybe_ref_tlb[T: TlbConstructor](self, deserializer: type[T] | Callable[[Slice], T]) -> T | None:
        c = self.load_maybe_ref()
        if c is None:
            return None
        cs = c.begin_parse()
        return cs.load_tlb(deserializer)
    
    def load_address(self) -> Address:
        from ..types.msg_address import Address
        return self.load_tlb(Address)
    
    def load_msg_address(self) -> MsgAddress:
        from ..types.msg_address import msg_address
        return self.load_tlb(msg_address)
    
    def load_msg_address_ext(self) -> MsgAddressExt:
        from ..types.msg_address import msg_address_ext
        return self.load_tlb(msg_address_ext)
    
    def load_msg_address_int(self) -> MsgAddressInt:
        from ..types.msg_address import msg_address_int
        return self.load_tlb(msg_address_int)
    
    def load_cell(self) -> OrdinaryCell:
        '''Use this to load the remaining bits and refs as Cell'''
        c = OrdinaryCell(
            data=frozenbitarray(self.c.data[self.ld:self.rd]),
            refs=self.c.refs[self.lr:self.rr]
        )
        self.ld = self.rd
        self.lr = self.rr
        return c
    
    def load_slice(self) -> Slice:
        '''Use this to load the remaining bits and refs as Slice'''
        return self.load_cell().begin_parse()
        
    def __repr__(self) -> str:
        data = f'{self.remaining_bits}[{self.c.data[self.ld:self.rd].tobytes().hex().upper()}]'
        return f'Slice({data} -> {self.remaining_refs} refs)'
    
    def __str__(self) -> str:
        c = self.to_cell()
        return str(c)
    
    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Slice):
            return False
        return self.to_cell() == value.to_cell()
    
    def __hash__(self) -> int:
        return hash(self.to_cell())
