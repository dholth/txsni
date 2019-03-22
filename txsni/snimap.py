import collections
import ssl

from functools import wraps

from zope.interface import implementer

from OpenSSL.SSL import Connection

from twisted.internet.interfaces import IOpenSSLServerConnectionCreator
from twisted.internet.ssl import CertificateOptions

from txsni.only_noticed_pypi_pem_after_i_wrote_this import (
    certificateOptionsFromPileOfPEM
)

ACME_TLS_1 = b'acme-tls/1'


class _NegotiationData(object):
    """
    A container for the negotiation data.
    """
    __slots__ = [
        'npnAdvertiseCallback',
        'npnSelectCallback',
        'alpnSelectCallback',
        'alpnProtocols'
    ]

    def __init__(self):
        self.npnAdvertiseCallback = None
        self.npnSelectCallback = None
        self.alpnSelectCallback = None
        self.alpnProtocols = None

    def negotiateNPN(self, context):
        if self.npnAdvertiseCallback is None or self.npnSelectCallback is None:
            return

        context.set_npn_advertise_callback(self.npnAdvertiseCallback)
        context.set_npn_select_callback(self.npnSelectCallback)

    def negotiateALPN(self, context):
        if self.alpnSelectCallback is None or self.alpnProtocols is None:
            return

        context.set_alpn_select_callback(self.alpnSelectCallback)
        context.set_alpn_protos(self.alpnProtocols)


def _detect_acme(buf):
    """
    Determine whether buf is probably acme-tls/1

    Example ClientHello from letsencrypt

    b'\x16\x03\x01\x00\xe9\x01\x00\x00\xe5\x03\x03r\xfaO\xbb\xd5\xbf\x9fh'\
    b'\x04\xc8\x90/\xbb\xa7\x01\xb6\x06\x9f\xf0\xd2\xc9\x7f\xb5\xc9Ox'\
    b'\x1a\xba\xbf\x9e}} C\x7fz\xd4\x11B\xfeG\x05:\xbeP\xb5\xf7\x1d\x8a'\
    b'\xc8b\xb8\xe2\xf0\xbc\xe1\x0e;F\x98\x8a\x04G\xcf\xd2\x00 \xc0/'\
    b'\xc00\xc0+\xc0,\xcc\xa8\xcc\xa9\xc0\x13\xc0\t\xc0\x14\xc0\n\x00'\
    b'\x9c\x00\x9d\x00/\x005\xc0\x12\x00\n\x01\x00\x00|3t\x00\x00\x00'\
    b'\x00\x00\x16\x00\x14\x00\x00\x11dingoskidneys.com\x00\x05\x00\x05'\
    b'\x01\x00\x00\x00\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18'\
    b'\x00\x19\x00\x0b\x00\x02\x01\x00\x00\r\x00\x18\x00\x16\x08\x04\x08'\
    b'\x05\x08\x06\x04\x01\x04\x03\x05\x01\x05\x03\x06\x01\x06\x03\x02'\
    b'\x01\x02\x03\xff\x01\x00\x01\x00\x00\x10\x00\r\x00\x0b\nacme-tls/1\x00'\
    b'\x12\x00\x00\x00+\x00\x07\x06\x03\x03\x03\x02\x03\x01'
    """
    return ACME_TLS_1 in buf


class _ConnectionProxy(object):
    """
    A basic proxy for an OpenSSL Connection object that returns a ContextProxy
    wrapping the actual OpenSSL Context whenever it's asked for.
    """
    def __init__(self, original, factory):
        self._obj = original
        self._factory = factory
        self._acme_tls_1 = False

    def get_context(self):
        """
        A basic override of get_context to ensure that the appropriate proxy
        object is returned.
        """
        ctx = self._obj.get_context()
        return _ContextProxy(ctx, self._factory)

    def bio_write(self, buf):
        """
        Look for acme in the first packet only.
        """
        self._acme_tls_1 = _detect_acme(buf)
        self.bio_write = self._obj.bio_write
        return self._obj.bio_write(buf)

    def __getattr__(self, attr):
        return getattr(self._obj, attr)

    def __setattr__(self, attr, val):
        if attr in ('_obj', '_factory'):
            self.__dict__[attr] = val
        else:
            setattr(self._obj, attr, val)

    def __delattr__(self, attr):
        return delattr(self._obj, attr)


class _ContextProxy(object):
    """
    A basic proxy object for the OpenSSL Context object that records the
    values of the NPN/ALPN callbacks, to ensure that they get set appropriately
    if a context is swapped out during connection setup.
    """
    def __init__(self, original, factory):
        self._obj = original
        self._factory = factory

    def set_npn_advertise_callback(self, cb):
        self._factory._npnAdvertiseCallbackForContext(self._obj, cb)
        return self._obj.set_npn_advertise_callback(cb)

    def set_npn_select_callback(self, cb):
        self._factory._npnSelectCallbackForContext(self._obj, cb)
        return self._obj.set_npn_select_callback(cb)

    def set_alpn_select_callback(self, cb):

        def alpn_callback(connection, protocols):
            """wrapped alpn_select_callback"""
            return self._factory.selectAlpn(lambda: cb(connection, protocols), connection, protocols)

        self._factory._alpnSelectCallbackForContext(self._obj, alpn_callback)
        return self._obj.set_alpn_select_callback(alpn_callback)

    def set_alpn_protos(self, protocols):
        self._factory._alpnProtocolsForContext(self._obj, protocols)
        return self._obj.set_alpn_protos(protocols)

    def __getattr__(self, attr):
        return getattr(self._obj, attr)

    def __setattr__(self, attr, val):
        if attr in ('_obj', '_factory'):
            self.__dict__[attr] = val
        else:
            return setattr(self._obj, attr, val)

    def __delattr__(self, attr):
        return delattr(self._obj, attr)

@implementer(IOpenSSLServerConnectionCreator)
class SNIMap(object):
    def __init__(self, mapping, acme_mapping=None):
        self.mapping = mapping
        self.acme_mapping = acme_mapping
        self._negotiationDataForContext = collections.defaultdict(
            _NegotiationData
        )
        try:
            self.context = self.mapping[b'DEFAULT'].getContext()
        except KeyError:
            self.context = CertificateOptions().getContext()
        self.context.set_tlsext_servername_callback(
            self.selectContext
        )
        self.counter = 0

    def selectAlpn(self, default, connection, protocols):
        """
        Trap alpn negotation.

        Acme works by sending a special certificate based on this negotiation.
        If such a certificate exists in self.acme_mapping, we will respond.

        OpenSSL design flaws prevent us from changing certificates here.
        Instead we detect acme earlier and send the certificate in
        selectContext()
        """
        if (not ACME_TLS_1 in protocols
            or not self.acme_mapping
            or not connection._acme_tls_1):
            return default()

        return ACME_TLS_1

    def selectContext(self, connection):
        mapping = self.mapping
        if connection._acme_tls_1 and self.acme_mapping:
            mapping = self.acme_mapping

        oldContext = connection.get_context()
        newContext = mapping[connection.get_servername()].getContext()

        negotiationData = self._negotiationDataForContext[oldContext]
        negotiationData.negotiateNPN(newContext)
        negotiationData.negotiateALPN(newContext)

        connection.set_context(newContext)

    def serverConnectionForTLS(self, protocol):
        """
        Construct an OpenSSL server connection.

        @param protocol: The protocol initiating a TLS connection.
        @type protocol: L{TLSMemoryBIOProtocol}

        @return: a connection
        @rtype: L{OpenSSL.SSL.Connection}
        """
        conn = Connection(self.context, None)
        return _ConnectionProxy(conn, self)

    def _npnAdvertiseCallbackForContext(self, context, callback):
        self._negotiationDataForContext[context].npnAdvertiseCallback = (
            callback
        )

    def _npnSelectCallbackForContext(self, context, callback):
        self._negotiationDataForContext[context].npnSelectCallback = callback

    def _alpnSelectCallbackForContext(self, context, callback):
        self._negotiationDataForContext[context].alpnSelectCallback = callback

    def _alpnProtocolsForContext(self, context, protocols):
        self._negotiationDataForContext[context].alpnProtocols = protocols


class HostDirectoryMap(object):
    def __init__(self, directoryPath):
        self.directoryPath = directoryPath

    def __getitem__(self, hostname):
        if hostname is None:
            hostname = b"DEFAULT"
        filePath = self.directoryPath.child(hostname).siblingExtension(".pem")
        if filePath.isfile():
            return certificateOptionsFromPileOfPEM(filePath.getContent())
        else:
            if isinstance(hostname, bytes):
                hostname = hostname.decode('latin1')
            raise KeyError("no pem file for " + hostname)
