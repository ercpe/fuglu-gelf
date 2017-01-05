# -*- coding: utf-8 -*-

import logging

import graypy

from fuglu.shared import AppenderPlugin, actioncode_to_string, Suspect, yesno


class GELFLogger(AppenderPlugin):
    def __init__(self, *args, **kwargs):
        super(GELFLogger, self).__init__(*args, **kwargs)
        self.requiredvars = {
            'loglevel': {
                'default': 'INFO',
                'description': 'Log level to use',
            },
            'log-source': {
                'default': 'false',
                'description': 'Log full message'
            },
            'gelf-host': {
                'default': 'localhost',
                'description': 'Hostname of the target server',
            },
            'gelf-port': {
                'default': '12201',
                'description': 'Port on the target server',
            },
        }
        
        self._log_level = None
        self._gelf_logger = None
    
    @property
    def log_level(self):
        if self._log_level is None:
            self._log_level = logging.getLevelName(self.config.get(self.section, 'loglevel'))
        return self._log_level
    
    @property
    def gelf_logger(self):
        if self._gelf_logger is None:
            self._gelf_logger = logging.getLogger('gelf-logger')
            self._gelf_logger.setLevel(self.log_level)
            
            host = self.config.get(self.section, 'gelf-host')
            port = self.config.getint(self.section, 'gelf-port')

            handler = graypy.GELFHandler(host, port)
            self._gelf_logger.addHandler(handler)
            self._logger().log(self.log_level, "Sending messages to GELF server at %s:%s on %s", host, port, self.log_level)

        return self._gelf_logger
    
    @property
    def log_source(self):
        return self.config.getboolean(self.section, 'log-source')
    
    def process(self, suspect, decision):
        extra_data = self.build_data(suspect, actioncode_to_string(decision))
        self._logger().log(self.log_level, "Suspect %s, data=%s", suspect.id, extra_data)
        self.gelf_logger.log(self.log_level, "Suspect %s" % suspect.id, extra=extra_data)
    
    def build_data(self, suspect, decision):
        prefix = "suspect"
        d = {}
        
        def _add_to_dict(result, obj, path):
            if isinstance(obj, (int, long, float, bool, basestring, unicode)):
                result['_'.join(path)] = obj
            else:
                items = obj if isinstance(obj, dict) else dict((attr, getattr(obj, attr, None)) for attr in dir(obj))
                for key, value in items.items():
                    if key.startswith('_') or value is None:
                        continue

                    if callable(value):
                        if isinstance(obj, Suspect) and key in ('is_spam', 'is_highspam', 'is_virus'):
                            value = value()
                        else:
                            continue
                    
                    if key == 'source' and isinstance(obj, Suspect) and not self.log_source:
                        continue
                    
                    if key in ('scantimes', 'decisions'):  # special case - list of tuples
                        value = dict(value)
                    if key == 'fuglu.scantime':  # special case: it's a string in tags
                        value = float(value)

                    if isinstance(value, bool):
                        value = yesno(value)

                    _add_to_dict(result, value, path + [key])
        
        _add_to_dict(d, {'decision': decision}, [prefix])
        _add_to_dict(d, {'subject', suspect.get_message_rep()['Subject'] or ""}, [prefix])
        _add_to_dict(d, suspect, [prefix])

        for i, rcvd in enumerate(reversed(self.info_from_rcvd(suspect))):
            helo, revdns, ip = rcvd
            _add_to_dict(d, {
                'helo': helo,
                'reverse_dns': revdns,
                'ip': ip
            }, [prefix, 'received_%s' % i])
        
        return d

    def info_from_rcvd(self, suspect):
        result = []

        rcvd_headers = suspect.get_message_rep().get_all('Received')
        if not rcvd_headers:
            return result

        for line in rcvd_headers:
            x = suspect._parse_rcvd_header(line)
            if x is not None:
                result.append(x)

        return result
