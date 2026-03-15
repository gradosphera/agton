from enum import Enum

class Network(Enum):
    mainnet = -239
    testnet = -3
    
    def chain_id(self) -> int:
        return self.value
    
    def is_mainnet(self) -> bool:
        return self == self.mainnet
    
    def is_testnet(self) -> bool:
        return self == self.testnet
