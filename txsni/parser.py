
from os.path import expanduser

from zope.interface import implementer

from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.endpoints import serverFromString
from twisted.plugin import IPlugin

from txsni.snimap import SNIMap
from txsni.snimap import HostDirectoryMap
from twisted.python.filepath import FilePath
from txsni.tlsendpoint import TLSEndpoint


@implementer(IStreamServerEndpointStringParser,
             IPlugin)
class SNIDirectoryParser(object):
    prefix = 'txsni'

    def parseStreamServer(self, reactor, pemdir, *args, **kw):
        def colonJoin(items):
            return ':'.join([item.replace(':', '\\:') for item in items])
        sub = colonJoin(list(args) + ['='.join(item) for item in kw.items()])
        subEndpoint = serverFromString(reactor, sub)
        mapping = HostDirectoryMap(FilePath(expanduser(pemdir)))
        acme_mapping = HostDirectoryMap(FilePath(expanduser(pemdir + '/acme')))
        contextFactory = SNIMap(mapping, acme_mapping)
        return TLSEndpoint(endpoint=subEndpoint,
                           contextFactory=contextFactory)


@implementer(IStreamServerEndpointStringParser,
             IPlugin)
class AcmeSNIParser(object):
    """
    Expects a ${BASEDIR} with certs/ and alpn-certs/ subdirectories.
    The second directory is used for acme-tls certificates.
    """
    prefix = 'acmesni'

    def parseStreamServer(self, reactor, pemdir, *args, **kw):
        from txsni.certmaps import PerHostnameDirectoryMap, PerHostnameFilesMap

        def colonJoin(items):
            return ':'.join([item.replace(':', '\\:') for item in items])
        sub = colonJoin(list(args) + ['='.join(item) for item in kw.items()])
        subEndpoint = serverFromString(reactor, sub)
        mapping = PerHostnameDirectoryMap(FilePath(expanduser(pemdir)).child('certs'))
        acme_mapping = PerHostnameFilesMap(FilePath(expanduser(pemdir)).child('alpn-certs'))
        contextFactory = SNIMap(mapping, acme_mapping)
        return TLSEndpoint(endpoint=subEndpoint,
                           contextFactory=contextFactory)

