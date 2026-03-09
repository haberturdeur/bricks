import os.path
from typing import Tuple

import pytest
from pytest_embedded_idf.dut import IdfDut
from pytest_embedded_idf.utils import idf_parametrize


@pytest.mark.esp32s3
@pytest.mark.disnet_multi_dut
@pytest.mark.parametrize(
    'count, app_path',
    [
        (
            2,
            f"{os.path.join(os.path.dirname(__file__), 'multi_dut', 'role_a')}|{os.path.join(os.path.dirname(__file__), 'multi_dut', 'role_b')}",
        ),
    ],
    indirect=True,
)
@idf_parametrize('target', ['esp32s3'], indirect=['target'])
def test_disnet_multi_dut_ping_pong(dut: Tuple[IdfDut, IdfDut]) -> None:
    node_a, node_b = dut

    node_a.expect_exact('disnet-test: READY role=A', timeout=30)
    node_b.expect_exact('disnet-test: READY role=B', timeout=30)

    node_b.expect_exact('disnet-test: RX ping', timeout=30)
    node_a.expect_exact('disnet-test: RX pong', timeout=30)
    node_b.expect_exact('disnet-test: RX ping-rel', timeout=30)
    node_a.expect_exact('disnet-test: RX pong-rel', timeout=30)
    node_a.expect_exact('disnet-test: TEST PASS', timeout=30)
