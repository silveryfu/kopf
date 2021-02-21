import asyncio
import base64
import copy
import json
import logging
import warnings
from typing import Any, Dict, Iterable, List, Mapping, Optional

from kopf.clients import creating, errors, patching
from kopf.engines import loggers
from kopf.reactor import causation, handling, lifecycles, registries
from kopf.storage import states
from kopf.structs import bodies, configuration, containers, ephemera, filters, \
                         handlers, patches, primitives, references, reviews

logger = logging.getLogger(__name__)


# Erroneous cases when an API operation is wrong, while the webhooks are fine.
# This error is raised from the admission handlers.
class AdmissionError(handling.PermanentError):
    def __init__(
            self,
            __msg: Optional[str] = None,
            code: Optional[int] = None,
    ) -> None:
        super().__init__(__msg)
        self.code = code


class WebhookError(Exception):
    """ Errors when a webhook request is wrong, not an API operation. """


class MissingDataError(WebhookError):
    """ An admission is requested but some expected data are missing. """


class MissingResourceError(WebhookError):
    """ An admission is made for a resource that the operator does not have. """


class AmbiguousResourceError(WebhookError):
    """ An admission is made for one resource, but we (somehow) found a few. """


# The actual and the only implementation of the `Callback` type.
async def serve_admission_request(
        # Required for all webhook servers, meaningless without it:
        request: reviews.Request,
        *,
        # Optional for webhook servers that can recognise this information:
        webhook: Optional[handlers.HandlerId] = None,
        headers: Optional[Mapping[str, str]] = None,
        sslpeer: Optional[Mapping[str, Any]] = None,
        # Injected by partial() from spawn_tasks():
        settings: configuration.OperatorSettings,
        memories: containers.ResourceMemories,
        memobase: ephemera.AnyMemo,
        registry: registries.OperatorRegistry,
        insights: references.Insights,
        indices: ephemera.Indices,
) -> reviews.Response:

    # Identify the resource to be used -- with all its meta-information (as discovered).
    resource_info = request.get('request', {}).get('resource', {})
    group = resource_info.get('group')
    version = resource_info.get('version')
    plural = resource_info.get('resource')
    selector = references.Selector(group=group, version=version, plural=plural)
    resources = selector.select(insights.resources)
    if not resources:
        raise MissingResourceError(f"The specified resource has no handlers: {resource_info}")
    elif len(resources) > 1:
        raise AmbiguousResourceError(f"The specified resource is ambiguous: {resource_info}")
    else:
        resource, *_ = resources

    # Reconstruct the cause specially for web handlers.
    operation = request.get('request', {}).get('operation')
    userinfo = request.get('request', {}).get('userInfo')
    new_body = request.get('request', {}).get('object')
    old_body = request.get('request', {}).get('oldObject')
    raw_body = new_body if new_body is not None else old_body
    if userinfo is None:
        raise MissingDataError("User info is missing from the admission request.")
    if raw_body is None:
        raise MissingDataError("Either old or new object is missing from the admission request.")

    memo = await memories.recall(raw_body, memo=memobase, ephemeral=operation=='CREATE')
    body = bodies.Body(raw_body)
    patch = patches.Patch()
    cause = causation.ResourceAdmissionCause(
        resource=resource,
        indices=indices,
        logger=loggers.LocalObjectLogger(body=body, settings=settings),
        patch=patch,
        memo=memo,
        body=body,
        dryrun=bool(request.get('request', {}).get('dryRun')),
        sslpeer=sslpeer if sslpeer is not None else {},  # to ensure typing
        headers=headers if headers is not None else {},  # to ensure typing
        userinfo=userinfo,
    )

    # Retrieve the handlers to be executed.
    # TODO:1: capture warnings (only UserWarning). Ensure they are never raised as errors.
    # TODO:2: should warning catching be done by execute_handlers_once()? the same as exception catching.
    handlers_ = registry._resource_admission.get_handlers(cause)
    handlers_ = [h for h in handlers_ if not webhook or h.id == webhook]
    state = states.State.from_scratch().with_handlers(handlers_)
    with warnings.catch_warnings(record=True) as recorded_warnings:
        warnings.simplefilter('always', category=UserWarning, append=True)
        outcomes = await handling.execute_handlers_once(
            lifecycle=lifecycles.all_at_once,
            settings=settings,
            handlers=handlers_,
            cause=cause,
            state=state,
            default_errors=handlers.ErrorsMode.PERMANENT,
        )
    # state = state.with_outcomes(outcomes)  # TODO: is this needed? used?

    allowed = all(outcome.exception is None for id, outcome in outcomes.items())
    print(f'outcomes={dict(outcomes)}')  # TODO: Remove
    print(f'warnings={repr(recorded_warnings)}')  # TODO: Remove

    # TODO: check outcomes, build the AdmissionResponse with permission, warnings, errors, new body.
    response = reviews.Response(
        apiVersion=request.get('apiVersion', 'admission.k8s.io/v1'),
        kind=request.get('kind', 'AdmissionReview'),
        response=reviews.ResponsePayload(
            uid=request.get('request', {}).get('uid', ''),
            allowed=allowed))
    if recorded_warnings:
        response['response']['warnings'] = [str(warning.message) for warning in recorded_warnings]
    # TODO: for deletion: admission webhook "mutate1.expr1.kopf.dev" attempted to modify the object, which is not supported for this operation
    if patch:
        response['response']['patchType'] = 'JSONPatch'
        response['response']['patch'] = base64.b64encode(json.dumps(patch.as_json_patch()).encode('utf-8')).decode('utf-8')

    # TODO: also handle PermanentError, TemporaryError, arbitrary Exceptions here.
    errors = [outcome.exception for outcome in outcomes.values() if isinstance(outcome.exception, AdmissionError)]
    if errors:
        response['response']['status'] = reviews.ResponseStatus(
            message=str(errors[0]),
            code=errors[0].code or 500,
        )
    return response


async def webhook_server(
        *,
        settings: configuration.OperatorSettings,
        registry: registries.OperatorRegistry,
        insights: references.Insights,
        webhookfn: reviews.WebhookFn,
        container: primitives.Container[reviews.ClientConfig],
) -> None:
    # TODO: LATER: try to autodetect the most suitable way if possible, fail if not detected.

    # Verify that the operator is configured properly (after the startup activities are done).
    has_admission = bool(registry._resource_admission.get_all_handlers())
    if settings.admission.server is None and has_admission:
        raise Exception("Admission server/tunnel is not configured, but admission handlers exist. "
                        "See https://kopf.readthedocs.io/en/stable/admission/")

    # Do not start the endpoints until resources are ready, or we generate 404 "Not Found".
    await insights.ready_resources.wait()

    # Communicate all the client configs the server yields: both the initial one and the updates.
    # On each such change, the configuration manager will wake up and reconfigure the webhooks.
    if settings.admission.server is not None:
        async for client_config in settings.admission.server(webhookfn):
            await container.set(client_config)


# TODO: move to primitives?
async def condition_chain(
        source: asyncio.Condition,
        target: asyncio.Condition,
) -> None:
    """
    A condition chain is a clean hack to attach one condition to another.

    It is a "clean" (not "dirty") hack to wake up the configuration managers
    when either the resources are revised (as seen in insights),
    or a new client config is yielded from the webhook server.
    """
    async with source:
        while True:
            await source.wait()
            async with target:
                target.notify_all()


async def validating_configuration_manager(
        *,
        registry: registries.OperatorRegistry,
        settings: configuration.OperatorSettings,
        insights: references.Insights,
        container: primitives.Container[reviews.ClientConfig],
) -> None:
    await configuration_manager(
        reason=handlers.Admission.VALIDATING,
        selector=references.VALIDATING_WEBHOOK,
        registry=registry, settings=settings,
        insights=insights, container=container,
    )

async def mutating_configuration_manager(
        *,
        registry: registries.OperatorRegistry,
        settings: configuration.OperatorSettings,
        insights: references.Insights,
        container: primitives.Container[reviews.ClientConfig],
) -> None:
    await configuration_manager(
        reason=handlers.Admission.MUTATING,
        selector=references.MUTATING_WEBHOOK,
        registry=registry, settings=settings,
        insights=insights, container=container,
    )


# TODO: next step: expose this via `kopf generate webhooks -n default -n kube-system --admission=... > webhook.yaml`
async def configuration_manager(
        *,
        reason: handlers.Admission,
        selector: references.Selector,
        registry: registries.OperatorRegistry,
        settings: configuration.OperatorSettings,
        insights: references.Insights,
        container: primitives.Container[reviews.ClientConfig],
) -> None:

    # Wait until the prerequisites for managing are available (scanned from the cluster).
    await insights.ready_resources.wait()
    resource = await insights.backbone.wait_for(selector)
    all_handlers = registry._resource_admission.get_all_handlers()
    all_handlers = [h for h in all_handlers if h.reason == reason]

    # Do nothing if not managed or if there are no handlers.
    # The root task is unavoidable, since the managed mode is only set at the startup activities.
    if settings.admission.managed is None or not all_handlers:
        await asyncio.Event().wait()
        return

    # Optionally (if configured), pre-create the configuration objects if they are absent.
    # Use the try-or-fail strategy instead of check-and-do -- to reduce the RBAC requirements.
    try:
        await creating.create_obj(resource=resource, name=settings.admission.managed)
    except errors.APIConflictError:
        pass  # exists already
    except errors.APIForbiddenError:
        logger.error(f"Not enough RBAC permissions to create a {resource}.")
        raise

    # Execute either when actually changed (yielded from the webhook server),
    # or the condition is chain-notified (from the insights: on resources/namespaces revision).
    # Ignore inconsistencies: they are expected -- the server fills the defaults.
    client: Optional[reviews.ClientConfig] = None
    try:
        async for client in container.as_changed():
            logger.info(f"Reconfiguring the {reason.value} webhook {settings.admission.managed}.")
            webhooks = _build_webhooks(
                all_handlers,
                resources=insights.resources,
                suffix=settings.admission.managed,
                client=client,
                persisted_only=False)
            await patching.patch_obj(
                resource=resource,
                namespace=None,
                name=settings.admission.managed,
                patch=patches.Patch({'webhooks': webhooks}),
            )
    finally:
        # Attempt to remove all managed webhooks, except for the strict ones.
        if client is not None:
            logger.info(f"Cleaning up the admission webhook {settings.admission.managed}.")
            webhooks = _build_webhooks(
                all_handlers,
                resources=insights.resources,
                suffix=settings.admission.managed,
                client=client,
                persisted_only=True)
            await patching.patch_obj(
                resource=resource,
                namespace=None,
                name=settings.admission.managed,
                patch=patches.Patch({'webhooks': webhooks}),
            )


def _build_webhooks(
        handlers_: Iterable[handlers.ResourceAdmissionHandler],
        resources: Iterable[references.Resource],
        *,
        client: reviews.ClientConfig,
        suffix: str,
        persisted_only: bool,
) -> List[Dict[str, Any]]:
    return [
        {
            # TODO: what if the id contains the field name? => replace to dots or dashes
            'name': f'{handler.id}.{suffix}',
            'sideEffects': 'NoneOnDryRun' if handler.side_effects else 'None',
            'failurePolicy': 'Ignore' if handler.ignore_failures else 'Fail',
            'matchPolicy': 'Equivalent',
            'rules': [
                {
                    'apiGroups': [resource.group],
                    'apiVersions': [resource.version],
                    'resources': [resource.plural],
                    'operations': ['*'] if handler.operation is None else [handler.operation],
                    'scope': '*',  # doesn't matter since a specific resource is used.
                }
                for resource in resources
                if handler.selector is not None  # None is used only in sub-handlers
                if handler.selector.check(resource)
            ],
            'objectSelector': _build_selector(handler.labels),
            'clientConfig': _inject_handler_id(client, handler.id),
            'timeoutSeconds': 30,  # a permitted maximum is 30.
            'admissionReviewVersions': ['v1', 'v1beta1'],  # only those understood by Kopf itself.
        }
        for handler in handlers_
        if not persisted_only or handler.persisted
    ]


def _build_selector(labels: Optional[filters.MetaFilter]) -> Optional[Mapping[str, Any]]:
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#resources-that-support-set-based-requirements
    return None if labels is None else {
        'matchExpressions': [
            {'key': key, 'operator': 'Exists'} if val is filters.MetaFilterToken.PRESENT else
            {'key': key, 'operator': 'DoesNotExist'} if val is filters.MetaFilterToken.ABSENT else
            # {'key': key, 'operator': 'In', 'values': list(val)} if isinstance(val, collections.abc.Iterable) and not isinstance(val, str) else
            {'key': key, 'operator': 'In', 'values': [str(val)]}
            for key, val in labels.items()
            if not callable(val)
        ]
    }


def _inject_handler_id(config: reviews.ClientConfig, id: handlers.HandlerId) -> reviews.ClientConfig:
    config = copy.deepcopy(config)

    url = config.get('url')
    if url is not None:
        config['url'] = f'{url.rstrip("/")}/{id}'

    service = config.get('service')
    if service is not None:
        path = service.get('path', '')
        service['path'] = f"{path}/{id}"

    return config
