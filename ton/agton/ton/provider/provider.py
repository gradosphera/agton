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
    def raw_send_external_message(self, message: bytes) -> None: ...

    @abstractmethod
    def run_get_method(self, address: Address, method: str, args: Iterable[TvmValue] = ()) -> tuple[TvmValue, ...]: ...

    @abstractmethod
    def get_account_state(self, address: Address) -> Account: ...

    @abstractmethod
    def get_account_transactions(self, address: Address) -> Iterator[tuple[Transaction, bytes]]: ...
    
    def send_external_message(self, message: Message) -> bytes:
        h = message.get_normalized_hash()
        self.raw_send_external_message(message.to_cell().to_boc())
        return h
