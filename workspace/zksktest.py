import pytest

from petlib.bn import Bn
from petlib.ec import EcGroup

from zksk import Secret
from zksk.pairings import BilinearGroupPair
from zksk.primitives.rangeproof import PowerTwoRangeStmt, RangeStmt, RangeOnlyStmt
from zksk.primitives.rangeproof import decompose_into_n_bits
from zksk.utils import make_generators
from zksk.utils.debug import SigmaProtocol


def test_range_stmt_non_interactive_outside_range(group):
    x = Secret(value=15)
    randomizer = Secret(value=group.order().random())

    g, h = make_generators(2, group)
    lo = 7
    hi = 15

    com = x * g + randomizer * h

    with pytest.warns(UserWarning):
        stmt = RangeStmt(com.eval(), g, h, lo, hi, x, randomizer)