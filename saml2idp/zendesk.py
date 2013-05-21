import base
import codex
import exceptions
import xml_render

class Processor(base.Processor):
    """
    Zendesk.com-specific SAML 2.0 AuthnRequest to Response Handler Processor.
    """
    def _decode_request(self):
        """
        Decodes request using both Base64 and Zipping.
        """
        self._request_xml = codex.decode_base64_and_inflate(self._saml_request)
    
    def _validate_request(self):
        """
        Validates the _saml_request. Sub-classes should override this and
        throw an Exception if the validation does not succeed.
        """
        super(Processor, self)._validate_request()
        if not '.zendesk.com/access/saml' in self._request_params['ACS_URL']:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a Zendesk URL.')

    def _format_assertion(self):
        
        self._assertion_xml = xml_render.get_assertion_zendesk_xml(self._assertion_params, signed=True)
