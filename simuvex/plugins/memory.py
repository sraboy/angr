#!/usr/bin/env python

import logging

l = logging.getLogger("simuvex.plguins.s_memory")

from .plugin import SimStatePlugin

from collections import defaultdict
from itertools import count

event_id = count()

class SimMemory(SimStatePlugin):
    def __init__(self):
        SimStatePlugin.__init__(self)

        self._events = defaultdict(dict)

    def store(self, addr, data, size, condition=None, fallback=None, bbl_addr=None, stmt_id=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'.
        '''
        raise NotImplementedError()

    def load(self, addr, size, condition=None, fallback=None, bbl_addr=None, stmt_id=None):
        raise NotImplementedError()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'.
        '''
        raise NotImplementedError()

    def add_event(self, event_type, details):
        id = event_id.next()
        self._events[event_type][id] = details

    def events(self, event_type):
        if event_type in self._events:
            return self._events[event_type]
        else:
            return None