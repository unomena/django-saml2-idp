from . import base
from . import exceptions
from . import xml_render

class Processor(base.Processor):
    """
    Django Response Handler Processor for testing against django-saml2-sp.
    """
    def _format_assertion(self):
        # NOTE: This uses the SalesForce assertion for the demo.
        self._assertion_xml = xml_render.get_assertion_salesforce_xml(self._assertion_params, signed=True)
