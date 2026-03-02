from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Self, Iterable, TYPE_CHECKING
from bitarray import bitarray, frozenbitarray
from bitarray.util import ba2int
from hashlib import sha256

from agton.ton.common.bitstring import BitString

from ..crypto.signing import sign, verify

if TYPE_CHECKING:
    from .slice import Slice
    from .builder import Builder

class Cell(ABC):
    MAX_BITS: int = 1023
    MAX_REFS: int = 4
    MAX_DEPTH: int = 1023

    def __init__(self,
                 data: BitString,
                 refs: Iterable[Cell] = (),
                 special: bool = False) -> None:
        self.data = data
        self.refs = tuple(refs)
        self.special = special
        if len(self.refs) > Cell.MAX_REFS:
            raise ValueError(f"Cell can have at most {Cell.MAX_REFS} references, got {len(self.refs)}")
        if len(self.data) > Cell.MAX_BITS:
            raise ValueError(f"Cell can have at most {Cell.MAX_BITS} bits in data, got {len(self.data)}")
    
    @property
    @abstractmethod
    def level(self) -> int: ...

    @classmethod
    def empty(cls) -> OrdinaryCell:
        return OrdinaryCell(data=frozenbitarray(), refs=())
    
    def _get_refs_descriptor(self, level: int = 0) -> bytes:
        d = len(self.refs) + 8 * self.special + 32 * level
        return d.to_bytes(1, 'big')

    def _get_bits_descriptor(self) -> bytes:
        b = len(self.data)
        d = b // 8 + (b + 7) // 8
        return d.to_bytes(1, 'big')

    def _get_descriptors(self, level: int = 0) -> bytes:
        return self._get_refs_descriptor(level) + self._get_bits_descriptor()

    def _get_data_bytes(self) -> bytes:
        result = bitarray(self.data)
        if len(result) % 8:
            result.append(1)
            result.fill()
        return result.tobytes()

    @abstractmethod
    def _depth(self, level: int) -> int: ...

    def depth(self, level: int | None = None) -> int:
        if level is None:
            level = self.level
        return self._depth(level)

    @abstractmethod
    def _hash(self, level: int) -> bytes: ...

    def hash(self, level: int | None = None) -> bytes:
        if level is None:
            level = self.level
        return self._hash(level)

    def to_boc(self, 
               with_crc: bool = False,
               with_index: bool = False,
               with_cache: bool = False,
               with_top_hash: bool = False,
               with_int_hashes: bool = False) -> bytes:
        from .boc import encode
        return encode([self], with_crc, with_index, with_cache, with_top_hash, with_int_hashes)
    
    @classmethod
    def from_boc(cls, b: bytes | str) -> Cell:
        from .boc import decode
        if isinstance(b, str):
            b = bytes.fromhex(b)
        roots = decode(b)
        if len(roots) != 1:
            raise ValueError(f'Expected exactly one root in BoC, but {len(roots)} found')
        return roots[0]
    
    def begin_parse(self) -> Slice:
        if self.special:
            raise ValueError("Can't parse exotic cells")
        from .slice import Slice
        return Slice(self, 0, len(self.data), 0, len(self.refs))
    
    def begin_parse_exotic(self) -> Slice:
        from .slice import Slice
        return Slice(self, 0, len(self.data), 0, len(self.refs))
    
    def to_slice(self) -> Slice:
        return self.begin_parse()
    
    def to_builder(self) -> Builder:
        from .builder import Builder
        if self.special:
            raise ValueError("Can't convert special cell to builder")
        b = Builder()
        b.data = bitarray(self.data)
        b.refs = list(self.refs)
        return b
    
    def sign(self, private_key: bytes) -> bytes:
        return sign(self.hash(), private_key)
    
    def verify(self, signature: bytes, public_key: bytes) -> bool:
        return verify(self.hash(), signature, public_key)
    
    def prune(self) -> PrunedBranchCell:
        hashes: list[bytes] = []
        depths: list[int] = []
        for l in range(self.level + 1):
            hashes.append(self.hash(l))
            depths.append(self.depth(l))
        return PrunedBranchCell(hashes, depths)
    
    def prove(self) -> MerkleProofCell:
        if self.level == 0:
            return MerkleProofCell(self.hash(self.level), self.depth(self.level), self)
        return MerkleProofCell(self.hash(self.level - 1), self.depth(self.level - 1), self)

    @abstractmethod
    def _type_name(self) -> str: ...

    def dump(self, d: int = 0, comma: bool = False) -> str:
        desc = ''
        if self.special:
            desc = f'* {self._type_name()} '
        data = f'{len(self.data)}[{self.data.tobytes().hex().upper()}]'
        refs = ''
        if self.refs:
            refs = ' -> {\n'
            for c in self.refs[:-1]:
                refs += '\t' * d + '\t' + c.dump(d + 1, comma=True) + '\n'
            refs += '\t' * d + '\t' + self.refs[-1].dump(d + 1) + '\n'
            refs += '\t' * d + '}'
        return desc + data + refs + (',' if comma else '')

    def __hash__(self) -> int:
        return hash(self.hash())
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Cell):
            return False
        return self.hash() == other.hash()

    def __repr__(self) -> str:
        desc = ''
        if self.special:
            desc = '* ' + self._type_name() + ' '
        return f"Cell({desc}{len(self.data)}[{self.data.tobytes().hex().upper()}] -> {len(self.refs)} refs)"

    def __str__(self) -> str:
        return self.dump()


class OrdinaryCell(Cell):
    def __init__(self,
                 data: frozenbitarray,
                 refs: Iterable[Cell] = ()) -> None:
        super().__init__(data, refs, False)

        self._level = 0
        for c in self.refs:
            self._level = max(self._level, c.level)

        self.depths: list[int] = []
        self.hashes: list[bytes] = []
        for l in range(self.level + 1):
            hasher = sha256()
            hasher.update(self._get_descriptors(l))
            hasher.update(self._get_data_bytes() if l == 0 else self.hashes[-1])
            for c in self.refs:
                hasher.update(c.depth(l).to_bytes(2, 'big'))
            for c in self.refs:
                hasher.update(c.hash(l))
            depth = 0
            for c in self.refs:
                depth = max(depth, c.depth(l) + 1)
            if depth > Cell.MAX_DEPTH:
                raise ValueError(f'Cell exceeded depth limit: {depth} > {Cell.MAX_DEPTH}')
            self.hashes.append(hasher.digest())
            self.depths.append(depth)

    @property
    def level(self) -> int:
        return self._level

    def _depth(self, level: int) -> int:
        level = min(level, self.level)
        return self.depths[level]

    def _hash(self, level: int) -> bytes:
        level = min(level, self.level)
        return self.hashes[level]

    def _type_name(self) -> str:
        return 'Ordinary'


class PrunedBranchCell(Cell):
    TAG = 1
    def __init__(self, hashes: Iterable[bytes], depths: Iterable[int]) -> None:
        hashes = tuple(hashes)
        depths = tuple(depths)
        
        self._level = len(hashes)
        if not (1 <= self._level <= 3):
            raise ValueError('Invalid level')
        if len(hashes) != self._level:
            raise ValueError('Hashes count should be equal to level')
        if len(depths) != self._level:
            raise ValueError('Depths count should be equal to level')
        
        from .builder import begin_cell
        b = (
            begin_cell()
            .store_uint(PrunedBranchCell.TAG, 8)
            .store_uint((1 << self.level) - 1, 8)
        )
        for h in hashes:
            b.store_bytes(h)
        for d in depths:
            b.store_uint(d, 16)
        super().__init__(BitString(b.data), [], True)
        hasher = sha256()
        hasher.update(self._get_descriptors(self._level))
        hasher.update(self._get_data_bytes())
        self.hashes = hashes + (hasher.digest(),)
        self.depths = depths + (0,)
    
    @classmethod
    def from_ordinary_cell(cls, c: Cell) -> Self:
        s = c.begin_parse()
        s.skip_prefix((PrunedBranchCell.TAG, 8))
        mask = s.load_uint(8)
        level = mask.bit_length()
        assert mask.bit_count() == level, 'This is too exotic'
        hashes = []
        depths = []
        for _ in range(level):
            hashes.append(s.load_bytes(32))
        for _ in range(level):
            depths.append(s.load_uint(16))
        s.end_parse()
        return cls(hashes, depths)

    @property
    def level(self) -> int:
        return self._level

    def _depth(self, level: int) -> int:
        level = min(level, self.level)
        return self.depths[level]

    def _hash(self, level: int) -> bytes:
        level = min(level, self.level)
        return self.hashes[level]

    def _type_name(self) -> str:
        return 'Pruned Branch'


class LibraryRefCell(Cell):
    TAG = 2
    def __init__(self, library_hash: bytes) -> None:
        self.library_hash = library_hash
        self._level = 0

        if len(library_hash) != 32:
            raise ValueError('Library hash should be 32 bytes')
        
        from .builder import begin_cell
        b = (
            begin_cell()
            .store_uint(LibraryRefCell.TAG, 8)
            .store_bytes(library_hash)
        )
        super().__init__(BitString(b.data), [], True)
        hasher = sha256()
        hasher.update(self._get_descriptors(self._level))
        hasher.update(self._get_data_bytes())
        self.hashes = [hasher.digest()]
        self.depths = [0]

    @classmethod
    def from_ordinary_cell(cls, c: Cell) -> Self:
        s = c.begin_parse()
        s.skip_prefix((LibraryRefCell.TAG, 8))
        library_hash = s.load_bytes(32)
        s.end_parse()
        return cls(library_hash)

    @property
    def level(self) -> int:
        return self._level

    def _depth(self, level: int) -> int:
        level = min(level, self.level)
        return self.depths[level]

    def _hash(self, level: int) -> bytes:
        level = min(level, self.level)
        return self.hashes[level]

    def _type_name(self) -> str:
        return 'Library Ref'


class MerkleProofCell(Cell):
    TAG = 3
    def __init__(self,
                 virtual_hash: bytes,
                 virtual_depth: int,
                 virtual_root: Cell) -> None:
        
        if len(virtual_hash) != 32:
            raise ValueError('Virtual hash should be 32 bytes')
        
        self.virtual_hash = virtual_hash
        self.virtual_depth = virtual_depth
        self.virtual_root = virtual_root

        self._level = max(virtual_root.level - 1, 0)

        from .builder import begin_cell
        b = (
            begin_cell()
            .store_uint(MerkleProofCell.TAG, 8)
            .store_bytes(self.virtual_hash)
            .store_uint(self.virtual_depth, 16)
        )
        super().__init__(BitString(b.data), [self.virtual_root], True)
        self.depths: list[int] = []
        self.hashes: list[bytes] = []
        for l in range(self.level + 1):
            hasher = sha256()
            hasher.update(self._get_descriptors(l))
            hasher.update(self._get_data_bytes() if l == 0 else self.hashes[-1])
            for c in self.refs:
                hasher.update(c.depth(l + 1).to_bytes(2, 'big'))
            for c in self.refs:
                hasher.update(c.hash(l + 1))
            depth = 0
            for c in self.refs:
                depth = max(depth, c.depth(l + 1) + 1)
            if depth > Cell.MAX_DEPTH:
                raise ValueError(f'Cell exceeded depth limit: {depth} > {Cell.MAX_DEPTH}')
            self.hashes.append(hasher.digest())
            self.depths.append(depth)

    @classmethod
    def from_ordinary_cell(cls, c: Cell) -> Self:
        s = c.begin_parse()
        s.skip_prefix((MerkleProofCell.TAG, 8))
        virtual_hash = s.load_bytes(32)
        virtual_depth = s.load_uint(16)
        virtual_root = s.load_ref()
        s.end_parse()
        return cls(virtual_hash, virtual_depth, virtual_root)

    @property
    def level(self) -> int:
        return self._level

    def _depth(self, level: int) -> int:
        level = min(level, self.level)
        return self.depths[level]

    def _hash(self, level: int) -> bytes:
        level = min(level, self.level)
        return self.hashes[level]

    def _type_name(self) -> str:
        return 'Merkle Proof'


class MerkleUpdateCell(Cell):
    TAG = 4
    def __init__(self,
                 old_hash: bytes,
                 new_hash: bytes,
                 old_depth: int,
                 new_depth: int,
                 old: Cell,
                 new: Cell) -> None:
        if not (len(old_hash) == len(new_hash) == 32):
            raise ValueError('Hashes should be 32 bytes')
        
        self.old_hash = old_hash
        self.new_hash = new_hash
        self.old_depth = old_depth
        self.new_depth = new_depth
        self.old = old
        self.new = new

        self._level = max(self.old.level - 1, self.new.level - 1, 0)

        from .builder import begin_cell
        b = (
            begin_cell()
            .store_uint(MerkleUpdateCell.TAG, 8)
            .store_bytes(self.old_hash)
            .store_bytes(self.new_hash)
            .store_uint(self.old_depth, 16)
            .store_uint(self.new_depth, 16)
        )
        super().__init__(BitString(b.data), [self.old, self.new], True)
        self.depths: list[int] = []
        self.hashes: list[bytes] = []
        for l in range(self.level + 1):
            hasher = sha256()
            hasher.update(self._get_descriptors(l))
            hasher.update(self._get_data_bytes() if l == 0 else self.hashes[-1])
            for c in self.refs:
                hasher.update(c.depth(l + 1).to_bytes(2, 'big'))
            for c in self.refs:
                hasher.update(c.hash(l + 1))
            depth = 0
            for c in self.refs:
                depth = max(depth, c.depth(l + 1) + 1)
            if depth > Cell.MAX_DEPTH:
                raise ValueError(f'Cell exceeded depth limit: {depth} > {Cell.MAX_DEPTH}')
            self.hashes.append(hasher.digest())
            self.depths.append(depth)

    @classmethod
    def from_ordinary_cell(cls, c: Cell) -> Self:
        s = c.begin_parse()
        s.skip_prefix((MerkleUpdateCell.TAG, 8))
        old_hash = s.load_bytes(32)
        new_hash = s.load_bytes(32)
        old_depth = s.load_uint(16)
        new_depth = s.load_uint(16)
        old = s.load_ref()
        new = s.load_ref()
        s.end_parse()
        return cls(old_hash, new_hash, old_depth, new_depth, old, new)

    @property
    def level(self) -> int:
        return self._level

    def _depth(self, level: int) -> int:
        level = min(level, self.level)
        return self.depths[level]

    def _hash(self, level: int) -> bytes:
        level = min(level, self.level)
        return self.hashes[level]

    def _type_name(self) -> str:
        return 'Merkle Update'
