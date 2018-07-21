# -*- coding: utf-8 -*-
from logging import Handler

import requests
from graypy.handler import BaseGELFHandler, WAN_CHUNK


class GELFHttpHandler(BaseGELFHandler, Handler):
    
    def __init__(self, host, port=443,
                 debugging_fields=True, extra_fields=True, fqdn=False,
                 localname=None, facility=None, level_names=False, compress=True):

        super(GELFHttpHandler, self).__init__(host, port, WAN_CHUNK, debugging_fields, extra_fields,
                                              fqdn, localname, facility, level_names, compress)
        Handler.__init__(self)
        
        self.host = host
        self.port = port

    def emit(self, record):
        
        try:
            msg = self.makePickle(record)

            url = "https://%s:%s/gelf" % (self.host, self.port)
            headers = {}
            if self.compress:
                headers['content-encoding'] = 'deflate'
            req = requests.post(url, data=msg, timeout=5.0, headers=headers)
            req.raise_for_status()
        except:
            self.handleError(record)

