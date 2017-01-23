# -*- coding: utf-8 -*-

import logging
from email.header import decode_header
from email.utils import getaddresses

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
        self.logger = self._logger()
    
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
            self.logger.log(self.log_level, "Sending messages to GELF server at %s:%s on %s", host, port, self.log_level)

        return self._gelf_logger
    
    @property
    def log_source(self):
        return self.config.getboolean(self.section, 'log-source')
    
    @property
    def recipient_delimiter(self):
        if self.config.has_option(self.section, 'recipient-delimiter'):
            return self.config.get(self.section, 'recipient-delimiter')
        return None
    
    def process(self, suspect, decision):
        extra_data = self.build_data(suspect, actioncode_to_string(decision))
        self.logger.log(self.log_level, "Suspect %s, data=%s", suspect.id, extra_data)
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
        
        _add_to_dict(d, {
            'decision': decision,
            'subject': self.get_subject(suspect),
            'envelope_from': self.cleaned_address(suspect.from_address),
            'envelope_to': self.cleaned_address(suspect.to_address, self.recipient_delimiter),
            'sender': self.get_mail_sender(suspect),
            'recipient': self.get_mail_recipient(suspect),
            'virus_names': self.get_virus_names(suspect),
        }, [prefix])
        _add_to_dict(d, suspect, [prefix])

        for i, rcvd in enumerate(reversed(self.info_from_rcvd(suspect))):
            helo, revdns, ip = rcvd
            _add_to_dict(d, {
                'helo': helo,
                'reverse_dns': revdns,
                'ip': ip
            }, [prefix, 'received_%s' % i])
        
        return d

    def get_mail_sender(self, suspect):
        msg = suspect.get_message_rep()

        if 'From' not in msg:
            return None

        try:
            return ', '.join([self.cleaned_address(addr) for _, addr in getaddresses(msg.get_all('From'))])
        except Exception as ex:
            self.logger.info("Failed to extract sender address from '%s': %s", s, ex)
            return ""

    def get_mail_recipient(self, suspect):
        msg = suspect.get_message_rep()

        if 'To' not in msg:
            return None

        try:
            return ', '.join([self.cleaned_address(addr, self.recipient_delimiter) for _, addr in getaddresses(msg.get_all('To'))])
        except Exception as ex:
            self.logger.info("Failed to extract recipient address: %s", ex)
            return ""

    def get_subject(self, suspect):
        msg = suspect.get_message_rep()
        raw_subject = msg['Subject'] or ""
        try:
            return ''.join([s for s, _ in decode_header(raw_subject)])
        except:
            return raw_subject

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

    def cleaned_address(self, addr, delimiter=None):
        s = (addr or "").lower().strip()
        if not s:
            return s

        if delimiter:
            localpart = s[:s.index('@')]
            domain = s[s.index('@')+1:]
            
            if delimiter in localpart:
                localpart = localpart[:localpart.index(delimiter)]
                return "%s@%s" % (localpart, domain)
        
        return s

    def get_virus_names(self, suspect):
        l = []
        
        for k in [scanner for scanner in suspect.tags.keys() if scanner.endswith('.virus')]:
            v = suspect.tags[k]
            
            if isinstance(v, dict):
                l.extend([x.strip() for x in v.values() if x.strip()])
        
        return ', '.join(l)
