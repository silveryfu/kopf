import warnings

import kopf


@kopf.on.startup()
def config(settings: kopf.OperatorSettings, **_):
    settings.admission.managed = 'auto.kopf.dev'
    # settings.admission.server = kopf.WebhookServer()
    # settings.admission.server = kopf.WebhookServer(certfile='../../cert.pem', pkeyfile='../../key.pem', port=1234)
    # settings.admission.server = kopf.WebhookK3dServer(certfile='../../k3d-cert.pem', pkeyfile='../../k3d-key.pem', port=1234)
    # settings.admission.server = kopf.WebhookK3dServer(port=1234, cadump='../../ca.pem', verify_cafile='../../client-cert.pem')
    # settings.admission.server = kopf.WebhookK3dServer(port=1234, cadump='../../ca.pem')
    # settings.admission.server = kopf.WebhookNgrokTunnel(binary="/usr/local/bin/ngrok", token='...', port=1234)
    settings.admission.server = kopf.WebhookNgrokTunnel(binary="/usr/local/bin/ngrok", port=1234, path='/xyz', region='eu')
    # settings.admission.server = kopf.WebhookInletsTunnel(...)


@kopf.on.validation('kex', persisted=True)
def validate1(spec, dryrun, **_):
    print(f'{dryrun=}')
    # warnings.warn("The default value is used. It is okay but worth changing.",
    #               kopf.AdmissionWarning)
    # warnings.warn("Whoa!", kopf.AdmissionWarning)  # TODO: not shown anywhere? kubectl --warnings-as-errors in 1.19?
    if spec.get('field') == 'value':
        raise kopf.AdmissionError("Meh! I don't like it. Change the field.")


@kopf.on.validation('kex')
def authhook(headers, sslpeer, **_):
    print(f'{headers=}')
    print(f'{sslpeer=}')
    if not sslpeer:
        warnings.warn("SSL peer is not identified.")
    else:
        common_name = None
        for key, val in sslpeer['subject'][0]:
            if key == 'commonName':
                common_name = val
                break
        else:
            warnings.warn("SSL peer's common name is absent.")
        if common_name is not None:
            warnings.warn(f"SSL peer is {common_name}.")


# @kopf.on.validation('kex')
# def validate2(**_):
#     raise kopf.AdmissionError("I'm too lazy anyway. Go away!", status=555)


# @kopf.on.mutation('kex')
# def mutate1(patch: kopf.Patch, **_):
#     patch.spec['injected'] = 123
