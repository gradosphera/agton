from __future__ import annotations

from typing import Self, Iterable, Iterator

from ..cell.cell import Cell

from ..provider import Provider
from ..types import Address, StateInit, MessageRelaxed, Message, CurrencyCollection, ExtraCurrencyCollection
from ..types import MsgAddressExt, AddrNone
from ..types import Transaction
from ..types import Account, AccountOrdinary, ActiveAccountState, UninitAccountState, FrozenAccountState
from ..types.tvm_value import TvmValue

class ContractError(Exception):
    pass

class Contract:
    def __init__(self, address: Address, provider: Provider) -> None:
        self.address = address
        self.provider = provider
    
    def run_get_method(self, method: str, args: Iterable[TvmValue] = ()) -> tuple[TvmValue, ...]:
        return self.provider.run_get_method(self.address, method, args)
    
    def send_external_message(self, msg: Message) -> bytes:
        return self.provider.send_external_message(msg)
    
    def create_internal_message(self, *,
                                value: int | CurrencyCollection = 0,
                                body: Cell = Cell.empty(),
                                bounce: bool = True,
                                init: StateInit | None = None) -> MessageRelaxed:
        return MessageRelaxed.internal(
            dest=self.address,
            value=value,
            body=body,
            bounce=bounce,
            init=init
        )
    
    def create_external_message(self,
                                body: Cell = Cell.empty(),
                                src: MsgAddressExt = AddrNone(),
                                init: StateInit | None = None) -> Message:
        return Message.external_in(
            src=src,
            dest=self.address,
            body=body,
            init=init
        )

    def get_account_state(self) -> Account:
        return self.provider.get_account_state(self.address)
    
    def get_transactions(self) -> Iterator[tuple[Transaction, bytes]]:
        return self.provider.get_account_transactions(self.address)

    def get_balance_with_extracurrency(self) -> CurrencyCollection:
        account = self.get_account_state()
        if not isinstance(account, AccountOrdinary):
            return CurrencyCollection(0, ExtraCurrencyCollection())
        return account.storage.balance
    
    def get_balance(self) -> int:
        return self.get_balance_with_extracurrency().grams
    
    def get_state_init(self) -> StateInit | None:
        account = self.get_account_state()
        if not isinstance(account, AccountOrdinary):
            return None
        state = account.storage.state
        if not isinstance(state, ActiveAccountState):
            return None
        return state.state_init
    
    def is_deployed(self) -> bool:
        return self.get_state_init() is not None

    def get_code(self) -> Cell | None:
        s = self.get_state_init()
        if s is None:
            return None
        return s.code
    
    def get_data(self) -> Cell | None:
        s = self.get_state_init()
        if s is None:
            return None
        return s.data

    def __repr__(self) -> str:
        contact_name = self.__class__.__name__
        formatted_address = self.address.format(testnet_only=self.provider.network.is_testnet())
        return f'{contact_name}({formatted_address})'
