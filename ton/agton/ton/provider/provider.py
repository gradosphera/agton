from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator

from agton.ton import Cell, Network, Address, Account, Transaction
from agton.ton.types.tvm_value import TvmValue
from agton.ton.crypto import crc16
from agton.ton import MsgAddressInt, Message


class ProviderError(Exception):
    pass


class Provider(ABC):
    def __init__(self, network: Network):
        self.network = network

    @abstractmethod
    def raw_run_get_method(
        self, 
        a: MsgAddressInt,
        method_id: int,
        stack: tuple[TvmValue, ...],
        method: str | None = None
    ) -> tuple[TvmValue, ...]: ...

    @abstractmethod
    def raw_send_external_message(self, message: bytes) -> None: ...

    @abstractmethod
    def get_account_state(self, address: Address) -> Account: ...

    @abstractmethod
    def get_account_transactions(self, address: Address) -> Iterator[Transaction]: ...
    
    def send_external_message(self, message: Message) -> bytes:
        h = message.get_normalized_hash()
        self.raw_send_external_message(message.to_cell().to_boc())
        return h

    def run_get_method(self,
                       a: MsgAddressInt,
                       method_id: int | str,
                       stack: Iterable[TvmValue] | TvmValue = ()) -> tuple[TvmValue, ...] | TvmValue:
        method_name_fallback = None if isinstance(method_id, int) else method_id
        if isinstance(method_id, str):
            t = int.from_bytes(crc16(method_id.encode()), byteorder='big')
            method_id = (t & 0xffff) | 0x10000
        if isinstance(stack, Iterable):
            stack = tuple(stack)
        else:
            stack = (stack,)
        s = self.raw_run_get_method(a, method_id, stack, method_name_fallback)

        if len(s) == 1:
            return s[0]
        return s
