"""
Several webhooks servers & tunnels supported out of the box.
"""
import asyncio
import base64
import functools
import ipaddress
import json
import logging
import ssl
import tempfile
import urllib.parse
from typing import AsyncIterator, Collection, Optional, Set, Tuple, Union

import aiohttp.web

from kopf.reactor import admission
from kopf.structs import reviews

logger = logging.getLogger(__name__)

LOCALHOST: str = 'localhost'
LOCALPORT: int = 54321


class MissingDependencyError(ImportError):
    """ A feature is used which requires an optional dev-mode dependency. """


class WebhookServer:
    """
    A local HTTP/HTTPS endpoint.

    Currently, the server is based on ``aiohttp``, but the implementation
    can change in the future without warning.

    This server is also used by specialised tunnels when they need
    a local endpoint to be tunneled.

    * ``addr``, ``port`` is where to listen for connections
      (defaults to ``localhost`` and ``9443``).
    * ``path`` is the root path for a webhook server
      (defaults to no root path).
    * ``host`` is an optional override of the hostname for webhook URLs;
      if not specified, the ``addr`` will be used.

    Kubernetes requires HTTPS, so HTTPS is the default mode of the server.
    This webhook server supports SSL both for the server certificates
    and for client certificates (e.g., for authentication) at the same time:

    * ``cadata``, ``cafile`` is the CA bundle to be passed as a "client config"
      to the webhook configuration objects, to be used by clients/apiservers
      when talking to the webhook server; it is not used in the server itself.
    * ``cadump`` is a path to save the resulting CA bundle to be used
      by clients, i.e. apiservers; it can be passed to ``curl --cacert ...``;
      if ``cafile`` is provided, it contains the same content.
    * ``certfile``, ``pkeyfile`` define the server's endpoint certificate;
      if not specified, a self-signed certificate and CA will be generated
      for both ``addr`` & ``host`` as SANs (but only ``host`` for CommonName).
    * ``password`` is either for decrypting the provided ``pkeyfile``,
      or for encrypting and decrypting the generated private key.
    * ``verify_mode``, ``verify_cafile``, ``verify_capath``, ``verify_cadata``
      will be loaded into the SSL context for verifying the client certificates
      when provided and if provided by the clients, i.e. apiservers or curl;
      (`ssl.SSLContext.verify_mode`, `ssl.SSLContext.load_verify_locations`).
    * ``insecure`` flag disables HTTPS and runs an HTTP webhook server.
      This is used in ngrok for a local endpoint, but can be used for debugging
      or when the certificate-generating dependencies/extras are not installed.
    """
    DEFAULT_HOST: Optional[str] = None

    addr: str
    port: int
    host: Optional[str]
    path: Optional[str]

    cadata: Optional[bytes]  # -> .webhooks.*.clientConfig.caBundle
    cafile: Optional[str]
    cadump: Optional[str]

    context: Optional[ssl.SSLContext]
    insecure: bool
    certfile: Optional[str]
    pkeyfile: Optional[str]
    password: Optional[str]

    verify_mode: Optional[ssl.VerifyMode]
    verify_cafile: Optional[str]
    verify_capath: Optional[str]
    verify_cadata: Optional[Union[str, bytes]]

    def __init__(
            self,
            *,
            # Listening socket, root URL path, and the reported URL hostname:
            addr: str = LOCALHOST,
            port: int = LOCALPORT,
            path: Optional[str] = None,
            host: Optional[str] = None,
            # The CA bundle to be passed to "client configs":
            cadata: Optional[bytes] = None,
            cafile: Optional[str] = None,
            cadump: Optional[str] = None,
            # A pre-configured SSL context (if any):
            context: Optional[ssl.SSLContext] = None,
            # The server's own certificate, or lack of it (loaded into the context):
            insecure: bool = False,  # http is needed for ngrok
            certfile: Optional[str] = None,
            pkeyfile: Optional[str] = None,
            password: Optional[str] = None,
            # Verification of client certificates (loaded into the context):
            verify_mode: Optional[ssl.VerifyMode] = None,
            verify_cafile: Optional[str] = None,
            verify_capath: Optional[str] = None,
            verify_cadata: Optional[Union[str, bytes]] = None,
    ) -> None:
        super().__init__()
        self.addr = addr
        self.port = port
        self.path = path
        self.host = host
        self.cadata = cadata
        self.cafile = cafile
        self.cadump = cadump
        self.context = context
        self.insecure = insecure
        self.certfile = certfile
        self.pkeyfile = pkeyfile
        self.password = password
        self.verify_mode = verify_mode
        self.verify_cafile = verify_cafile
        self.verify_capath = verify_capath
        self.verify_cadata = verify_cadata

    async def __call__(self, webhookfn: reviews.WebhookFn) -> AsyncIterator[reviews.ClientConfig]:
        cadata, context = self._build_ssl()
        serve = functools.partial(self._serve, webhookfn)
        path = self.path.rstrip('/') if self.path else ''
        app = aiohttp.web.Application()
        app.add_routes([aiohttp.web.post(f"{path}/{{id:.*}}", serve)])
        runner = aiohttp.web.AppRunner(app, handle_signals=False)
        await runner.setup()
        try:
            site = aiohttp.web.TCPSite(runner, self.addr, self.port, ssl_context=context)
            await site.start()

            # Log with the actual URL: normalised, with hostname/port set.
            listening_url = accessing_url = self._build_url(self.addr, self.port, self.path or '')
            logger.debug(f"Listening for webhooks at {listening_url}")
            host = self.host or self.DEFAULT_HOST
            if host:
                accessing_url = self._build_url(host, self.port, self.path or '')
                logger.debug(f"Accessing the webhooks at {accessing_url}")

            client_config = reviews.ClientConfig(url=accessing_url)
            if cadata is not None:
                client_config['caBundle'] = base64.b64encode(cadata).decode('ascii')

            yield client_config
            await asyncio.Event().wait()
        finally:
            # On any reason of exit, stop serving the endpoint.
            await runner.cleanup()

    async def _serve(
            self,
            webhookfn: reviews.WebhookFn,
            request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        """
        Serve a single admission request: an aiohttp-specific implementation.

        Mind 2 different ways the errors are reported:

        * Directly by the webhook's response, i.e. to the apiservers.
          This means that the webhook request was done improperly;
          the original API request might be good, but we could not confirm that.
        * In ``.response.status``, as apiservers send it to the requesting user.
          This means that the original API operation was done improperly,
          while the webhooks are functional.
        """
        # The extra information that is passed down to handlers for authentication/authorization.
        # Note: this is an identity of an apiserver, not of the user that sends an API request.
        headers = dict(request.headers)
        sslpeer = request.transport.get_extra_info('peercert') if request.transport else None
        webhook = request.match_info.get('id')
        try:
            text = await request.text()
            data = json.loads(text)
            response = await webhookfn(data, webhook=webhook, sslpeer=sslpeer, headers=headers)
            return aiohttp.web.json_response(response)
        except admission.AmbiguousResourceError as e:
            raise aiohttp.web.HTTPConflict(reason=str(e))
        except admission.MissingResourceError as e:
            raise aiohttp.web.HTTPNotFound(reason=str(e))
        except admission.WebhookError as e:
            raise aiohttp.web.HTTPBadRequest(reason=str(e))
        except json.JSONDecodeError as e:
            raise aiohttp.web.HTTPBadRequest(reason=str(e))

    @staticmethod
    def _build_url(host: str, port: int, path: str) -> str:
        netloc = host if port == 443 else f'{host}:{port}'
        return urllib.parse.urlunsplit(['https', netloc, path, '', ''])

    def _build_ssl(self) -> Tuple[Optional[bytes], Optional[ssl.SSLContext]]:
        """
        A macros to construct an SSL context, possibly generating SSL certs.

        Returns a CA bundle to be passed to the "client configs",
        and a properly initialised SSL context to be used by the server.
        Or ``None`` for both if an HTTP server is needed.
        """
        cadata = self.cadata
        context = self.context
        if self.insecure and self.context is not None:
            raise ValueError("Insecure mode cannot have an SSL context specified.")

        # Read the provided CA bundle for webhooks' "client config"; not used by the server itself.
        if cadata is None and self.cafile is not None:
            with open(self.cafile, 'rb') as f:
                cadata = f.read()

        # Kubernetes does not work with HTTP, so we do not bother and always run HTTPS too.
        # Except when explicitly said to be insecure, e.g. by ngrok (free plan only supports HTTP).
        if context is None and not self.insecure:
            context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

        if context is not None:

            # Load a CA for verifying the client certificates (if provided) by this server.
            if self.verify_mode is not None:
                context.verify_mode = self.verify_mode
            if self.verify_cafile or self.verify_capath or self.verify_cadata:
                logger.debug("Loading a CA for client certificate verification.")
                context.load_verify_locations(
                    self.verify_cafile,
                    self.verify_capath,
                    self.verify_cadata,
                )
                if context.verify_mode == ssl.CERT_NONE:
                    context.verify_mode = ssl.CERT_OPTIONAL

            # Load the specified server's certificate, or generate a self-signed one if possible.
            # If cafile/cadata are not defined, use the server's certificate as a CA for clients.
            if self.certfile is not None and self.pkeyfile is not None:
                logger.debug("Using a provided certificate for HTTPS.")
                context.load_cert_chain(
                    self.certfile,
                    self.pkeyfile,
                    self.password,
                )
                if cadata is None and self.certfile is not None:
                    with open(self.certfile, 'rb') as f:
                        cadata = f.read()
            else:
                logger.debug("Generating a self-signed certificate for HTTPS.")
                hostnames = [self.host or self.DEFAULT_HOST or self.addr, self.addr]
                certdata, pkeydata = _build_self_signed_cert(hostnames, self.password)
                with tempfile.NamedTemporaryFile() as certf, tempfile.NamedTemporaryFile() as pkeyf:
                    certf.write(certdata)
                    pkeyf.write(pkeydata)
                    certf.flush()
                    pkeyf.flush()
                    context.load_cert_chain(certf.name, pkeyf.name, self.password)

                # For a self-signed certificate, the CA bundle is the certificate itself,
                # regardless of what cafile/cadata are provided from outside.
                cadata = certdata

        # Dump the provided or self-signed CA (but not the key!), e.g. for `curl --cacert ...`
        if self.cadump is not None and cadata is not None:
            with open(self.cadump, 'wb') as f:
                f.write(cadata)

        return cadata, context


class WebhookK3dServer(WebhookServer):
    """
    A tunnel from inside of K3d/K3s to its host where the operator is running.

    With this tunnel, a developer can develop the webhooks when fully offline,
    since all the traffic is local and never leaves the host machine.

    The forwarding is maintained by K3d itself. This tunnel only replaces
    the endpoints for the Kubernetes webhook and injects an SSL certificate
    with proper CN/SANs --- to match Kubernetes's SSL validity expectations.
    """
    DEFAULT_HOST = 'host.k3d.internal'


class WebhookMinikubeServer(WebhookServer):
    """
    A tunnel from inside of Minikube to its host where the operator is running.

    With this tunnel, a developer can develop the webhooks when fully offline,
    since all the traffic is local and never leaves the host machine.

    The forwarding is maintained by Minikube itself. This tunnel only replaces
    the endpoints for the Kubernetes webhook and injects an SSL certificate
    with proper CN/SANs --- to match Kubernetes's SSL validity expectations.
    """
    DEFAULT_HOST = 'host.minikube.internal'


class WebhookNgrokTunnel:
    """
    Tunnel admission webhook request via an external tunnel: ngrok_.

    .. _ngrok: https://ngrok.com/

    ``addr``, ``port``, and ``path`` have the same meaning as in
    `kopf.WebhookServer`: where to listen for connections locally.
    Ngrok then tunnels this endpoint remotely with.

    Mind that the ngrok webhook tunnel runs the local webhook server
    in an insecure (HTTP) mode. For secure (HTTPS) mode, a paid subscription
    and properly issued certificates are needed. This goes beyond Kopf's scope.
    If needed, implement your own ngrok tunnel.

    Besides, ngrok tunnel does not report any CA to the webhook client configs.
    It is expected that the default trust chain is sufficient for ngrok's certs.

    ``token`` can be used for paid subscriptions, which lifts some limitations.
    Otherwise, the free plan has a limit of 40 requests per minute
    (this should be enough for local development).

    ``binary``, if set, will use the specified ``ngrok`` binary path;
    otherwise, ``pyngrok`` downloads the binary at runtime (not recommended).

    .. warning::

        The public URL is not properly protected and a malicious user
        can send requests to a locally running operator. If the handlers
        only process the data and make no side effects, this should be fine.

        Despite ngrok provides basic auth ("username:password"),
        Kubernetes does not permit this information in the URLs.

        Ngrok partially "protects" the URLS by assigning them random hostnames.
        Additionally, you can add random paths. However, this is not "security",
        only a bit of safety for a short time (enough for development runs).
    """
    addr: str
    port: int
    path: Optional[str]
    token: Optional[str]
    region: Optional[str]
    binary: Optional[str]

    def __init__(
            self,
            *,
            addr: str = LOCALHOST,
            port: int = LOCALPORT,
            path: Optional[str] = None,
            token: Optional[str] = None,
            region: Optional[str] = None,
            binary: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.addr = addr
        self.port = port
        self.path = path
        self.token = token
        self.region = region
        self.binary = binary

    async def __call__(self, webhookfn: reviews.WebhookFn) -> AsyncIterator[reviews.ClientConfig]:
        try:
            from pyngrok import conf, ngrok
        except ImportError:
            raise MissingDependencyError(
                "Using ngrok webhook tunnel requires an extra dependency: "
                "run `pip install pyngrok` or `pip install kopf[dev]`."
            )

        if self.binary is not None:
            conf.get_default().ngrok_path = self.binary
        if self.region is not None:
            conf.get_default().region = self.region
        if self.token is not None:
            ngrok.set_auth_token(self.token)

        # Ngrok only supports HTTP with a free plan; HTTPS requires a paid subscription.
        local_server = WebhookServer(addr=self.addr, port=self.port, path=self.path, insecure=True)
        tunnel: Optional[ngrok.NgrokTunnel] = None
        loop = asyncio.get_running_loop()
        try:
            async for _ in local_server(webhookfn):

                # Re-create the tunnel for each new local endpoint (if it changes at all).
                if tunnel is not None:
                    await loop.run_in_executor(None, ngrok.disconnect, tunnel.public_url)
                tunnel = await loop.run_in_executor(
                    None, functools.partial(ngrok.connect, f'{self.port}', bind_tls=True))

                # Adjust for local webhook server specifics (no port, but with the same path).
                # Report no CA bundle -- ngrok's certs (Let's Encrypt) are in a default trust chain.
                url = f"{tunnel.public_url}{self.path or ''}"
                logger.debug(f"Accessing the webhooks at {url}")
                yield reviews.ClientConfig(url=url)  # e.g. 'https://e5fc05f6494b.ngrok.io/xyz'
        finally:
            if tunnel is not None:
                await loop.run_in_executor(None, ngrok.disconnect, tunnel.public_url)


class WebhookInletsTunnel:
    """
    TODO
    """

    def __init__(
            self,
            *,
            port: Optional[int] = None,
            license: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.port = port
        self.license = license

    async def __call__(self, webhookfn: reviews.WebhookFn) -> AsyncIterator[reviews.ClientConfig]:
        yield reviews.ClientConfig()  # TODO!!!


def _build_self_signed_cert(
        hostnames: Collection[str],
        password: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    """
    Build a self-signed certificate with SANs (subject alternative names).

    Returns a tuple of a certificate and its private key in the PEM format.

    The certificate is "minimally sufficient", without much of the extra
    information on the subject besides its common and alternative names.
    However, IP addresses are properly recognised for better compatibility.
    The first hostname (or an IP address) is used as a common name.

    ``certbuilder`` is used as an implementation because it is lightweight:
    2.9 MB vs. 8.7 MB for cryptography. Still, it is too heavy to include
    as a normal runtime dependency (for 8.8 MB of Kopf itself), so it is
    only available as the ``kopf[dev]`` extra for development-mode dependencies.
    """
    try:
        import certbuilder
        import oscrypto.asymmetric
    except ImportError:
        raise MissingDependencyError(
            "Using self-signed certificates requires an extra dependency: "
            "run `pip install certbuilder` or `pip install kopf[dev]`. "
            "Or pass `insecure=True` to a webhook server to use only HTTP. "
            "Or generate your own certificates and pass as certfile=/pkeyfile=."
        )

    # Detect which ones of the hostnames are probably IPv4/IPv6 addresses.
    # Also bring them all to their canonical forms.
    ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
    for hostname in hostnames:
        try:
            ips.add(ipaddress.IPv4Address(hostname))
        except ipaddress.AddressValueError:
            pass
        try:
            ips.add(ipaddress.IPv6Address(hostname))
        except ipaddress.AddressValueError:
            pass

    # Remove non-accessible but bindable addresses like 0.0.0.0.
    ips = {ip for ip in ips if not ip.is_unspecified}

    # Build the certificate.
    subject = {'common_name': next(iter(hostnames))}
    public_key, private_key = oscrypto.asymmetric.generate_pair('rsa', bit_size=2048)
    pkeypemdata = oscrypto.asymmetric.dump_private_key(private_key, password)
    builder = certbuilder.CertificateBuilder(subject, public_key)
    builder.ca = True
    builder.key_usage = {'digital_signature', 'key_encipherment', 'key_cert_sign', 'crl_sign'}
    builder.extended_key_usage = {'server_auth', 'client_auth'}
    builder.self_signed = True
    builder.subject_alt_ips = list({str(ip) for ip in ips})  # deduplicate
    builder.subject_alt_domains = list(set(hostnames))  # deduplicate
    certificate = builder.build(private_key)
    certpemdata = certbuilder.pem_armor_certificate(certificate)
    return certpemdata, pkeypemdata
