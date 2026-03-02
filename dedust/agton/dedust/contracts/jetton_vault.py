from agton.ton import Cell, Contract, MessageRelaxed, CurrencyCollection, to_nano
from agton.ton.types import MsgAddress, MsgAddressInt, AddrNone
from agton.jetton import JettonWallet, JettonTransfer

from ..payloads import SwapPayload, DepositLiquidityPayload
from ..types import SwapStep
from ..types import SwapParams
from ..types import PoolParams

class JettonVault(Contract):
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
                            jetton_wallet: JettonWallet,
                            query_id: int,
                            amount: int,
                            response_destination: MsgAddress,
                            swap_step: SwapStep,
                            swap_params: SwapParams,
                            value: int | CurrencyCollection = to_nano(0.5),
                            forward_amount: int = to_nano(0.3)) -> MessageRelaxed:
        swap_payload = SwapPayload(swap_step, swap_params)
        return jetton_wallet.create_jetton_transfer(
            value=value,
            query_id=query_id,
            amount=amount,
            destination=self.address,
            response_destination=response_destination,
            forward_amount=forward_amount,
            forward_payload=swap_payload.to_cell()
        )
    
    def create_deposit_liquidity_payload(
        self,
        pool_params: PoolParams,
        min_lp_amount: int,
        asset0_target_balance: int,
        asset1_target_balance: int,
        fulfill_payload: Cell | None = None,
        reject_payload: Cell | None = None
    ) -> DepositLiquidityPayload:
        return DepositLiquidityPayload(
            pool_params, min_lp_amount,
            asset0_target_balance, asset1_target_balance,
            fulfill_payload, reject_payload
        )
    
    def create_deposit_liquidity_message(
        self,
        jetton_wallet: JettonWallet,
        response_destination: MsgAddress,
        query_id: int,
        amount: int,
        pool_params: PoolParams,
        min_lp_amount: int,
        asset0_target_balance: int,
        asset1_target_balance: int,
        fulfill_payload: Cell | None = None,
        reject_payload: Cell | None = None,
        value: int | CurrencyCollection = to_nano(0.5),
        forward_amount: int = to_nano(0.3)
    ) -> MessageRelaxed:
        deposit_liquidity_payload = DepositLiquidityPayload(
            pool_params, min_lp_amount,
            asset0_target_balance, asset1_target_balance,
            fulfill_payload, reject_payload
        )
        return jetton_wallet.create_jetton_transfer(
            value=value,
            query_id=query_id,
            amount=amount,
            destination=self.address,
            response_destination=response_destination,
            forward_amount=forward_amount,
            forward_payload=deposit_liquidity_payload.to_cell()
        )