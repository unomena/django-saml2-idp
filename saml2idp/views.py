import logging

from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.http import HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

from . import saml2idp_metadata
from . import exceptions
from . import metadata
from . import registry
from . import xml_signing


def _generate_response(request, processor):
    """
    Generate a SAML response using processor and return it in the proper Django
    response.
    """
    if processor:
        try:
            tv = processor.generate_response()
        except exceptions.UserNotAuthorized:
            return render(
                request,
                'saml2idp/invalid_user.html'
            )
    else:
        return render(
            request,
            'saml2idp/invalid_request.html',
            status=400
        )

    return render(
        request,
        'saml2idp/login.html',
        tv
    )


def xml_response(request, template, tv):
    return render(
        request,
        template,
        tv,
        content_type="application/xml"
    )


@csrf_exempt
def login_begin(request, *args, **kwargs):
    """
    Receives a SAML 2.0 AuthnRequest from a Service Provider and
    stores it in the session prior to enforcing login.
    """
    if request.method == 'POST':
        source = request.POST
    else:
        source = request.GET
    # Store these values now, because Django's login cycle won't preserve them.

    if source.get('SAMLRequest'):
        request.session['SAMLRequest'] = source['SAMLRequest']
    elif source.get('samlrequest'):
        request.session['SAMLRequest'] = source['samlrequest']
    else:
        return HttpResponseBadRequest('No SAML request information provided')

    if source.get('RelayState'):
        request.session['RelayState'] = source['RelayState']
    elif source.get('relaystate'):
        request.session['RelayState'] = source['relaystate']
    else:
        return HttpResponseBadRequest('No RelayState information provided')

    return redirect('idp_login_process')


@csrf_exempt
@login_required
def login_init(request, resource, **kwargs):
    """
    Initiates an IdP-initiated link to a simple SP resource/target URL.
    """
    sp_config = metadata.get_config_for_resource(resource)
    proc_path = sp_config['processor']
    proc = registry.get_processor(proc_path)
    try:
        linkdict = dict(metadata.get_links(sp_config))
        pattern = linkdict[resource]
    except KeyError:
        raise ImproperlyConfigured(
            'Cannot find link resource in SAML2IDP_REMOTE setting: "%s"'
            % resource
        )
    is_simple_link = ('/' not in resource)
    if is_simple_link:
        simple_target = kwargs['target']
        url = pattern % simple_target
    else:
        url = pattern % kwargs
    proc.init_deep_link(request, sp_config, url)
    return _generate_response(request, proc)


@login_required
def login_process(request):
    """
    Processor-based login continuation.
    Presents a SAML 2.0 Assertion for POSTing back to the Service Provider.
    """
    # reg = registry.ProcessorRegistry()
    logging.debug("Request: %s" % request)

    proc = registry.find_processor(request)
    return _generate_response(request, proc)


@csrf_exempt
def logout(request):
    """
    Allows a non-SAML 2.0 URL to log out the user and
    returns a standard logged-out page. (SalesForce and others use this method,
    though it's technically not SAML 2.0).
    """
    auth.logout(request)
    tv = {}
    return render(
        request,
        'saml2idp/logged_out.html',
        tv
    )


@login_required
@csrf_exempt
def slo_logout(request):
    """
    Receives a SAML 2.0 LogoutRequest from a Service Provider,
    logs out the user and returns a standard logged-out page.
    """
    request.session['SAMLRequest'] = request.POST['SAMLRequest']
    # TODO: Parse SAML LogoutRequest from POST data, similar to login_process()
    # TODO: Add a URL dispatch for this view.
    # TODO: Modify the base processor to handle logouts?
    # TODO: Combine this with login_process(), since they are so very similar?
    # TODO: Format a LogoutResponse and return it to the browser.
    # XXX: For now, simply log out without validating the request.
    auth.logout(request)
    tv = {}
    return render(
        request,
        'saml2idp/logged_out.html',
        tv
    )


def descriptor(request):
    """
    Replies with the XML Metadata IDSSODescriptor.
    """
    idp_config = saml2idp_metadata.SAML2IDP_CONFIG
    entity_id = idp_config['issuer']
    slo_url = request.build_absolute_uri(reverse('idp_logout'))
    sso_url = request.build_absolute_uri(reverse('idp_login_begin'))
    pubkey = xml_signing.load_cert_data(idp_config['certificate_file'])
    tv = {
        'entity_id': entity_id,
        'cert_public_key': pubkey,
        'slo_url': slo_url,
        'sso_url': sso_url,

    }
    return xml_response(
        request,
        'saml2idp/idpssodescriptor.xml',
        tv
    )
