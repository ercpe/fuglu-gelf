# -*- coding: utf-8 -*-
import logging

import graypy

from fuglu.shared import AppenderPlugin, actioncode_to_string


class GELFLogger(AppenderPlugin):
    
    def __init__(self, *args, **kwargs):
        super(GELFLogger, self).__init__(*args, **kwargs)
        self.requiredvars = {
            'loglevel': {
                'default': 'INFO',
                'description': 'Log level to use',
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
    
            handler = graypy.GELFHandler(self.config.get(self.section, 'gelf-host'),
                                         self.config.getint(self.section, 'gelf-port'))
            self._gelf_logger.addHandler(handler)
        return self._gelf_logger

    def process(self, suspect, decision):
        self.gelf_logger.log(self.log_level, "Suspect %s" % suspect.id,
                             extra=self.build_data(suspect, actioncode_to_string(decision)))

    def build_data(self, suspect, decision):
        prefix = "suspect"
        d = {}

        def _add_to_dict(result, obj, path):
            if isinstance(obj, (int, long, float, bool, basestring, unicode)):
                result['_'.join(path)] = obj
            else:
                items = obj if isinstance(obj, dict) else dict((attr, getattr(obj, attr, None)) for attr in dir(obj))
                for k, v in items.items():
                    if k.startswith('_') or v is None or callable(v):
                        continue
                    
                    if k in ('scantimes', 'decisions'):  # special case - list of tuples
                        v = dict(v)
                    if k == 'fuglu.scantime':  # special case: it's a string in tags
                        v = float(v)

                    _add_to_dict(result, v, path + [k])
        
        _add_to_dict(d, {'decision': decision}, [prefix])
        _add_to_dict(d, suspect, [prefix])

        return d
