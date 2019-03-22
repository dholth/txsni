import collections

from functools import wraps

from zope.interface import implementer

from OpenSSL.SSL import Connection

from twisted.internet.interfaces import IOpenSSLServerConnectionCreator
from twisted.internet.ssl import CertificateOptions

from txsni.only_noticed_pypi_pem_after_i_wrote_this import (
    certificateOptionsFromPileOfPEM
)


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


class _ConnectionProxy(object):
    """
    A basic proxy for an OpenSSL Connection object that returns a ContextProxy
    wrapping the actual OpenSSL Context whenever it's asked for.
    """
    def __init__(self, original, factory):
        self._obj = original
        self._factory = factory

    def get_context(self):
        """
        A basic override of get_context to ensure that the appropriate proxy
        object is returned.
        """
        ctx = self._obj.get_context()
        return _ContextProxy(ctx, self._factory)

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

        @wraps(cb)
        def alpn_callback(connection, protocols):
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
            self.context = self.mapping['DEFAULT'].getContext()
        except KeyError:
            self.context = CertificateOptions().getContext()
        self.context.set_tlsext_servername_callback(
            self.selectContext
        )

    def selectAlpn(self, default, connection, protocols):
        """
        Trap alpn negotation, possibly intervene to choose a new certificate
        or protocol. Needs to happen after servername.

        Acme works by sending a special certificate based on this negotiation.
        If such a certificate exists in self.acme_mapping, we will respond.

        The acme protocol doesn't need to send or receive other data.
        """
        ACME_TLS_1 = b'acme-tls/1'
        if not ACME_TLS_1 in protocols or not self.acme_mapping:
            return default()
        self.selectContext(connection, mapping=self.acme_mapping)
        # does this mess up 'normal' connections to the same context?
        # is this really a context from a separate directory?
        connection.get_context().set_alpn_protos([ACME_TLS_1])
        return ACME_TLS_1

    def selectContext(self, connection, mapping=None):
        mapping = mapping or self.mapping

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
            hostname = "DEFAULT"
        filePath = self.directoryPath.child(hostname).siblingExtension(".pem")
        if filePath.isfile():
            return certificateOptionsFromPileOfPEM(filePath.getContent())
        else:
            raise KeyError("no pem file for " + hostname)
