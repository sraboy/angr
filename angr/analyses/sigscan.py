from . import Analysis, register_analysis
import nampa
import os

import logging
l = logging.getLogger('angr.analyses.sigscan')


class SigScan(Analysis):
    def __init__(self, method, rename=False, binary=None, **kwargs):
        self.binary  = binary if binary is not None else self.project.loader.main_object
        self.method  = method.lower()
        self.rename  = rename
        self.bs      = self.obj.binary_stream
        self.scanner = None

        if method == 'flirt':
            self.scanner = Flirt(**kwargs)
            self.scanner.scan()

    @property
    def matches(self):
        return self.scanner.matches

    @property
    def sym_func_addrs(self):
        return [k for k,v in self.obj.symbols_by_addr if v.is_function is True]

    @property
    def kb_func_addrs(self):
        if not hasattr('functions', self.project.kb):
            l.warn('No functions in KnowledgeBase. Try running a CFG.')
            return []
        return [k for k,v in self.project.kb.functions if not v.is_syscall and not v.is_simprocedure]

    @property
    def cfg_unnamed_node_addrs(self):
        return [f.addr for f in self.project.cfg.nodes() if f.name is None ]

    def scan(self):
        l.warn('This method is meant to be overridden in derived classes. Returning empty list.')
        return []
        
# TODO: HACK for nampa
# The callback from nampa has to be a static method so we
# keep a reference to the currently-running instance. We should
# probably just put in a PR to add the ability to pass an
# additional parameter, and we can pass the instance there
# flirtinstance = None

class FlirtScan(SigScan):
    def __init__(self, **kwargs):
        self.matches    = []
        self.callback   = kwargs.get('callback', _nampa_callback)
        self.signatures = self.load_signatures(kwargs.get('sigpath', os.getcwd()))
        self.addrlist   = self.get_addrs()

        FlirtScan._cur_instance = self      # Bit of a hack for nampa. See above.

    #
    # Static vars
    #
    _cur_instance   = None
    _FUNCTION_TAIL_LENGTH = 0x100

    @staticmethod
    def _nampa_callback(addr, func):
        match = Match(func, addr, flirtinstance.project)
        FlirtScan._cur_instance.matches.append(match)

    def scan(self):
        self._match_addrs(self.addrs)

    def _load_signatures(self):
        sigfiles = []
        if os.path.isfile(sigpath):
            sigfiles.append(sigpath)
        elif os.path.isdir(sigpath):
            sigfiles.extend([os.path.join(sigpath, f) for f in next(os.walk(sigpath))[2]])

        signatures = []
        for sf in sigfiles:
            with open(sf, 'rb') as sigfile:
                signatures.append(nampa.parse_flirt_file(sigfile))

        return signatures

    def _get_addrs(self):
        user_addrs      = kwargs.get('addrs', [])
        exclude_addrs   = kwargs.get('exclude', [])
        sym_addrs       = []
        kb_addrs        = []
        cfg_node_addrs  = []

        if kwargs.get('use_sym', False) is True:
            sym_addrs = self.sym_func_addrs()
        if kwargs.get('use_kb', False) is True:
            kb_addrs = self.kb_func_addrs()
        if kwargs.get('use_cfg_nodes', False) is True:
            cfg_node_addrs = self.cfg_unnamed_node_addrs()

        return set(user_addrs + sym_addrs + kb_addrs + cfg_node_addrs) - set(exclude_addrs)

    def _match_addrs(self):
        for s in self.signatures:
            l.debug('Scanning %d addresses with SIG for %s', len(self.addrlist), s.header.library_name)
            for addr in self.addrlist:
                start = addr ^ self.obj.mapped_base
                end = addr + 32
                self.bs.seek(start, 0)
                buf = self.bs.read(end - start + FlirtScan._FUNCTION_TAIL_LENGTH)
                nampa.match_functions(s, buf, start, self.callback)


class Match:
    def __init__(self, func, addr, project):
        self.match_sym_name = False
        self.match_sym_addr = False
        self.match_kb       = False
        self.flirtfunc      = func
        self.flirtaddr      = addr | project.main_object.mapped_base

        self.check_symbols()
        self.check_kb()

    def check_symbols(self):
        sym = project.loader.main_object.get_symbol(self.flirtfunc.name)
        if sym is not None:
            self.match_sym_name = True
        if self.flirtaddr in mainobj.symbols_by_addr:
            self.match_sym_addr = True

    def check_kb(self):
        if self.flirtaddr in project.kb.functions:
            self.match_kb = True
register_analysis(SigScan, 'SigScan')
