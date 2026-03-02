from agton.ton import Contract

from agton.ton import Cell, to_nano
from agton.ton.types import MessageRelaxed
from agton.ton.types import CurrencyCollection
from agton.ton.types import AddrNone, MsgAddress, MsgAddressInt

from ..messages import Swap, DepositLiquidity
from ..types import SwapStep
from ..types import SwapParams
from ..types import PoolParams, Volatile


class NativeVault(Contract):
    def create_swap_params(self, 
                           recepient_addr: MsgAddressInt,
                           deadline: int = 0,
                           referral_addr: MsgAddress = AddrNone(),
                           fulfill_payload: Cell | None = None,
                           reject_payload: Cell | None = None) -> SwapParams:
        return SwapParams(
            deadline, recepient_addr, referral_addr, fulfill_payload, reject_payload
        )

    def create_swap_message(self,
                            query_id: int,
                            amount: int,
                            swap_step: SwapStep,
                            swap_params: SwapParams) -> MessageRelaxed:
        swap_body = Swap(query_id, amount, swap_step, swap_params)
        swap_message = self.create_internal_message(
            value=amount + to_nano('0.2'),
            body=swap_body.to_cell()
        )
        return swap_message

    def create_deposit_liquidity_message(self,
                                         query_id: int,
                                         amount: int,
                                         pool_params: PoolParams,
                                         min_lp_amount: int,
                                         asset0_target_balance: int,
                                         asset1_target_balance: int,
                                         fulfill_payload: Cell | None = None,
                                         reject_payload: Cell | None = None) -> MessageRelaxed:
            deposit_liquidity_body = DepositLiquidity(
                query_id, amount, pool_params,
                min_lp_amount, asset0_target_balance, asset1_target_balance,
                fulfill_payload, reject_payload
            )
            return self.create_internal_message(
                value=amount + to_nano('0.3'),
                body=deposit_liquidity_body.to_cell(),
            )
