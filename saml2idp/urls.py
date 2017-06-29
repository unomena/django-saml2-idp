from django.conf.urls import *

from saml2idp.views import (
    descriptor,
    login_begin,
    login_init,
    login_process,
    logout
)

from metadata import get_deeplink_resources


def deeplink_url_patterns(
        prefix='',
        url_base_pattern=r'^init/%s/$',
        login_init_func=login_init):
    """
    Returns new deeplink URLs based on 'links' from settings.SAML2IDP_REMOTES.
    Parameters:
    - url_base_pattern - Specify this if you need non-standard deeplink URLs.
        NOTE: This will probably closely match the 'login_init' URL.
    """
    resources = get_deeplink_resources()
    new_patterns = []
    for resource in resources:
        new_patterns += patterns(
            prefix,
            url(
                url_base_pattern % resource,
                login_init_func,
                {
                    'resource': resource,
                },
            )
        )
    return new_patterns


urlpatterns = patterns(
    '',
    url(r'^login/$', login_begin, name="idp_login_begin"),
    url(r'^login/process/$', login_process, name='idp_login_process'),
    url(r'^logout/$', logout, name="idp_logout"),
    (r'^metadata/xml/$', descriptor),
    # For "simple" deeplinks:
    url(
        r'^init/(?P<resource>\w+)/(?P<target>\w+)/$',
        login_init,
        name="idp_login_init"
    ),
)
# Issue 13 - Add new automagically-created URLs for deeplinks:
urlpatterns += deeplink_url_patterns()
