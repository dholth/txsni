"""
{ hostname : certificate } maps compatible with the way the
https://dehydrated.io/ acme client stores its certificates.
"""

from txsni.only_noticed_pypi_pem_after_i_wrote_this import (
    certificateOptionsFromPileOfPEM
)

class PerHostnameDirectoryMap(object):
    """
    Per-hostname subdirectories with two pem's.
    """

    def __init__(self, directoryPath, keyName='privkey.pem', fullchainName='fullchain.pem'):
        self.directoryPath = directoryPath
        self.keyName = keyName
        self.chainName = fullchainName

    def __getitem__(self, hostname):
        if hostname is None:
            hostname = b"DEFAULT"
        hostPath = self.directoryPath.child(hostname)
        keyPath = hostPath.child(self.keyName)
        fullchainPath = hostPath.child(self.chainName)
        if keyPath.isfile() and fullchainPath.isfile():
            return certificateOptionsFromPileOfPEM(
                keyPath.getContent() + fullchainPath.getContent()
            )
        else:
            raise KeyError("no pem files for " + hostname.decode('charmap'))


class PerHostnameFilesMap(object):
    """
    Two per-hostname pem's in a single direcotry.
    """

    def __init__(self, directoryPath):
        self.directoryPath = directoryPath

    def __getitem__(self, hostname):
        certPath = self.directoryPath.child(hostname).siblingExtension(".crt.pem")
        keyPath = self.directoryPath.child(hostname).siblingExtension(".key.pem")
        if certPath.isfile() and keyPath.isfile():
            return certificateOptionsFromPileOfPEM(
                keyPath.getContent() + certPath.getContent()
            )
        else:
            raise KeyError("no pem files for " + hostname.decode("charmap"))
