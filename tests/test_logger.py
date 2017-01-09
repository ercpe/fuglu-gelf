# -*- coding: utf-8 -*-
import os
import sys

if sys.version_info < (3, 0, 0):
    from ConfigParser import ConfigParser
else:
    from configparser import ConfigParser

import os
from fuglu.shared import Suspect

from fuglugelf.logger import GELFLogger


class TestLogger(object):
    
    def test_get_subject(self):
        plugin = GELFLogger(ConfigParser())
        f = os.path.join(os.path.dirname(__file__), '01-subject.eml')
        suspect = Suspect("sender@example.com", "suspect@example.com", f)
        
        assert plugin.get_subject(suspect) == "***SPAM***Webseite enthüllt: So verdient man 512 € am Tag automatisch"

    def test_clean_address(self):
        plugin = GELFLogger(ConfigParser())
        
        assert plugin.cleaned_address(None) == ""
        assert plugin.cleaned_address("") == ""
        assert plugin.cleaned_address(" sender@example.com ") == "sender@example.com"
        assert plugin.cleaned_address("SENDER@EXAMPLE.COM") == "sender@example.com"

        assert plugin.cleaned_address("recipient+test@example.com") == "recipient+test@example.com"
        assert plugin.cleaned_address("recipient@example.com", '+') == "recipient@example.com"
        assert plugin.cleaned_address("recipient+test@example.com", "+") == "recipient@example.com"
