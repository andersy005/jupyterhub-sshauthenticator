# flake8: noqa
from pkg_resources import DistributionNotFound, get_distribution

from sshauthenticator.auth import SSHAuthenticator

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    # package is not installed
    __version__ = '0.0.0'
