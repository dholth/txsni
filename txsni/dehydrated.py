"""
{ hostname : certificate } maps compatible with the way the
https://dehydrated.io/ acme client stores its certificates.
"""

import pem.twisted


class DehydratedMap(object):
    """
    Dehydrated's certs, in per-hostname subdirectories
    """

    def __init__(self, directoryPath):
        self.directoryPath = directoryPath

    def __getitem__(self, hostname):
        if hostname is None:
            hostname = b"DEFAULT"
        hostPath = self.directoryPath.child(hostname)
        keyPath = hostPath.child("privkey.pem")
        fullchainPath = hostPath.child("fullchain.pem")
        if keyPath.isfile() and fullchainPath.isfile():
            return pem.twisted.certificateOptionsFromFiles(
                keyPath.path, fullchainPath.path
            )
        else:
            raise KeyError("no pem file for " + hostname.decode("latin1"))


class DehydratedAcmeMap(object):
    """
    Dehydrated's acme-tls/1 certs, in a single directory
    """

    def __init__(self, directoryPath):
        self.directoryPath = directoryPath

    def __getitem__(self, hostname):
        certPath = self.directoryPath.child(hostname).siblingExtension(".crt.pem")
        keyPath = self.directoryPath.child(hostname).siblingExtension(".key.pem")
        if certPath.isfile() and keyPath.isfile():
            return pem.twisted.certificateOptionsFromFiles(keyPath.path, certPath.path)
        else:
            raise KeyError("no acme cert for " + hostname.decode("latin1"))
