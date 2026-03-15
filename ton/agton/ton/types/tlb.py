from abc import ABC, abstractmethod
from typing import final, Self

from ..cell.cell import Cell
from ..cell.slice import Slice
from ..cell.builder import Builder
from ..common import BitString
from ..common.bitstring import int2bs

class TlbDeserializationError(Exception):
    pass

class TlbConstructor(ABC):
    @classmethod
    @abstractmethod
    def tag(cls) -> tuple[int, int] | None: ...

    @classmethod
    @abstractmethod
    def deserialize_fields(cls, s: Slice) -> Self: ...

    @abstractmethod
    def serialize_fields(self, b: Builder) -> Builder: ...

    @staticmethod
    def _normalize_tag(tag: tuple[int, int] | None) -> BitString:
        if tag is None:
            return BitString()
        return int2bs(tag[0], tag[1])

    @final
    @classmethod
    def deserialize(cls, s: Slice) -> Self:
        try:
            s.skip_prefix(TlbConstructor._normalize_tag(cls.tag()))
        except Exception:
            raise TlbDeserializationError('Tag mismatch')
        return cls.deserialize_fields(s)

    @final
    def serialize(self, b: Builder | None = None) -> Builder:
        if b is None:
            b = Builder()
        b.store_bits(TlbConstructor._normalize_tag(self.tag()))
        self.serialize_fields(b)
        return b

    def to_builder(self) -> Builder:
        return self.serialize()

    def to_cell(self) -> Cell:
        return self.serialize().end_cell()

    def to_slice(self) -> Slice:
        return self.to_cell().begin_parse()

    @classmethod
    def from_slice(cls, s: Slice) -> Self:
        c = cls.deserialize(s)
        s.end_parse()
        return c

    @classmethod
    def from_cell(cls, c: Cell) -> Self:
        return cls.from_slice(c.begin_parse())
    
    @classmethod
    def try_from_cell(cls, c: Cell) -> Self | None:
        try:
            return cls.from_slice(c.begin_parse())
        except Exception:
            return None
