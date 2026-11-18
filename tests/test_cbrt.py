"""Cube-root stand-in for math.cbrt (Python 3.11+) in the KFX drmsdk stages.

The result is truncated to an integer right away, so a stand-in must agree with
math.cbrt exactly; x ** (1/3) does not (64 ** (1/3) truncates to 3).
"""
import math
import random

import pytest

from kfx_stages.drmsdk import joint_pure_math as jpm

CUBES = [float(n) ** 3 for n in range(0, 2_100_000, 997)] + [64.0, 27.0, 1000.0, 2.0 ** 63]


def _samples():
    rng = random.Random(1234)
    # the call site passes a sum of squares of signed 32/64-bit values
    return CUBES + [rng.uniform(0, 2.0 ** 64) for _ in range(20000)] + [rng.uniform(0, 1e6) for _ in range(20000)]


@pytest.mark.parametrize("n", [1, 4, 10, 99, 1000, 2097151])
def test_pure_is_exact_on_perfect_cubes(n):
    assert jpm._cbrt_pure(float(n) ** 3) == float(n)


def test_pure_handles_zero_and_sign():
    assert jpm._cbrt_pure(0.0) == 0.0
    assert jpm._cbrt_pure(-8.0) == -2.0


def test_libm_stand_in_is_reachable_here():
    # the pure fallback is a last resort; on Linux/macOS/Windows ctypes finds libm
    assert jpm._cbrt_libm() is not None


@pytest.mark.skipif(not hasattr(math, "cbrt"), reason="math.cbrt is Python 3.11+")
def test_libm_stand_in_is_bit_identical_to_math_cbrt():
    # math.cbrt wraps the C library cbrt, so on 3.8-3.10 the ctypes route gives the
    # very same doubles -- including glibc's inexact 6978.999999999999 for 6979**3
    libm = jpm._cbrt_libm()
    for x in _samples():
        assert libm(x) == math.cbrt(x), x


@pytest.mark.skipif(not hasattr(math, "cbrt"), reason="math.cbrt is Python 3.11+")
def test_pure_stand_in_is_close_to_math_cbrt():
    # glibc's cbrt is itself up to 2 ulp off on some perfect cubes (116649**3 gives
    # 116648.99999999997) where the pure version is exact, so allow a few ulp
    for x in _samples():
        ref = math.cbrt(x)
        assert abs(jpm._cbrt_pure(x) - ref) <= 4 * math.ulp(ref), x
