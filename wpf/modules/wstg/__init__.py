"""WSTG runners — one class per WSTG-XXX-NN test."""
from . import _base, info, conf, idnt, athn, athz, sess, inpv, errh, cryp, busl, clnt, apit  # noqa: F401
from ._base import REGISTRY, WstgTest, ManualChecklistTest  # noqa: F401

__all__ = ["REGISTRY", "WstgTest", "ManualChecklistTest"]
