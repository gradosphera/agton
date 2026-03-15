from .cell.cell import Cell
from .cell.builder import begin_cell

def to_units(value: str | int, decimals: int) -> int:
    if isinstance(value, int):
        return value * 10**decimals
    integer, _, fraction = value.partition('.')
    if len(fraction) > decimals:
        raise ValueError('fraction precision exceed decimal places')
    integer = int(integer)
    fraction = int(fraction.ljust(decimals, '0'))
    return integer * 10**decimals + fraction

def from_units(units: int, decimals: int, precision: int | None = None) -> str:
    if precision is None:
        precision = decimals
    units = round(units, precision - decimals)
    integer, fraction = divmod(units, 10**decimals)
    fraction = str(fraction).zfill(precision)[:precision]
    if fraction:
        return f'{integer}.{fraction}'
    return str(integer)

def to_nano(value: str | int) -> int:
    return to_units(value, 9)

def from_nano(units: int, precision: int | None = None) -> str:
    return from_units(units, 9, precision)

def comment(s: str) -> Cell:
    return (
        begin_cell()
        .store_uint(0, 32)
        .store_snake_string(s)
        .end_cell()
    )
