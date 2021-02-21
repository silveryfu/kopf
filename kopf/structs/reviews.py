from typing import Any, AsyncIterator, Awaitable, Callable, List, Mapping, Optional, Union

from typing_extensions import Literal, Protocol, TypedDict

from kopf.structs import bodies

Operation = Literal['CREATE', 'UPDATE', 'DELETE', 'CONNECT']


class RequestKind(TypedDict):
    group: str
    version: str
    kind: str


class RequestResource(TypedDict):
    group: str
    version: str
    resource: str


class UserInfo(TypedDict):
    username: str
    uid: str
    groups: List[str]


class CreateOptions(TypedDict, total=False):
    apiVersion: Literal["meta.k8s.io/v1"]
    kind: Literal["CreateOptions"]


class UpdateOptions(TypedDict, total=False):
    apiVersion: Literal["meta.k8s.io/v1"]
    kind: Literal["UpdateOptions"]


class DeleteOptions(TypedDict, total=False):
    apiVersion: Literal["meta.k8s.io/v1"]
    kind: Literal["DeleteOptions"]


class RequestPayload(TypedDict):
    uid: str
    kind: RequestKind
    resource: RequestResource
    requestKind: RequestKind
    requestResource: RequestResource
    userInfo: UserInfo
    name: str
    namespace: Optional[str]
    operation: Operation
    options: Union[None, CreateOptions, UpdateOptions, DeleteOptions]
    dryRun: bool
    object: bodies.RawBody
    oldObject: Optional[bodies.RawBody]


class Request(TypedDict):
    apiVersion: Literal["admission.k8s.io/v1"]
    kind: Literal["AdmissionReview"]
    request: RequestPayload


class ResponseStatus(TypedDict, total=False):
    code: int
    message: str


class ResponsePayload(TypedDict, total=False):
    uid: str
    allowed: bool
    warnings: Optional[List[str]]
    status: Optional[ResponseStatus]
    patch: Optional[str]
    patchType: Optional[Literal["JSONPatch"]]


class Response(TypedDict):
    apiVersion: Literal["admission.k8s.io/v1"]
    kind: Literal["AdmissionReview"]
    response: ResponsePayload


class ClientService(TypedDict, total=False):
    namespace: Optional[str]
    name: Optional[str]
    path: Optional[str]
    port: Optional[int]


# TODO: rename as AdmissionClientConfig or WebhookClientConfig or WebhookConfig, as per the docs (since exported via the public namespace).
class ClientConfig(TypedDict, total=False):
    url: Optional[str]
    service: Optional[ClientService]
    caBundle: Optional[str]


# The declaration how it must be accepted and called by custom webhook servers.
class WebhookFn(Protocol):
    def __call__(
            self,
            request: Request,
            *,
            webhook: Optional[str] = None,
            headers: Optional[Mapping[str, str]] = None,
            sslpeer: Optional[Mapping[str, Any]] = None,
    ) -> Awaitable[Response]: ...


# A server (either a coroutine or a callable object).
WebhookServerProtocol = Callable[[WebhookFn], AsyncIterator[ClientConfig]]
