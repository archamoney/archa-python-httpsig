from importlib.metadata import version, PackageNotFoundError

from .sign import Signer, HeaderSigner
from .verify import Verifier, HeaderVerifier
from .sign_algorithms import *

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    # package is not installed
    pass

__all__ = (Signer, HeaderSigner, Verifier, HeaderVerifier)
