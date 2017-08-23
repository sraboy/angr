from . import Analysis, register_analysis
import nampa
import os

import logging
l = logging.getLogger('angr.analyses.sigscan')
l.setLevel(logging.INFO)

class Match:
    """
    Defines a positive match, or 'find', from a signature scan
    """
    def __init__(self, func, addr, kb, binary, rename_kb):
        self.match_sym_name = False
        self.match_sym_addr = False
        self.match_kb       = False
        self.flirtfunc      = func
        self.flirtaddr      = addr
        self.kb             = kb
        self.binary         = binary

        if self.binary is not None:
            self.check_symbols()
        if self.kb is not None:
            self.check_kb()

        if rename_kb and self.match_kb: # match_kb verifies not only that kb is not None
            self.do_rename()            # but also that the address was found within it

    def check_symbols(self):
        sym = self.binary.get_symbol(self.flirtfunc.name)
        if sym is not None:
            self.match_sym_name = True
        if self.flirtaddr ^ self.binary.mapped_base in self.binary.symbols_by_addr:
            self.match_sym_addr = True

    def check_kb(self):
        if self.flirtaddr ^ self.binary.mapped_base in self.kb.functions:
            self.match_kb = True

    def do_rename(self):
        if self.flirtaddr ^ self.binary.mapped_base in self.kb.functions:


class SigScan(Analysis):
    """
    Angr Analysis base class for signature scanning. It provides default values to the signature scanners
    based on the current project, or as specified.
    """
    def __init__(self, method, rename=False, binary=None, cfg=None, use_sym=True, \
                 use_kb=True, use_cfg_nodes=False, addrs=[], exclude=[], doscan=True, **kwargs):
        """
        :param method:          The type of signature scan to do
        :param rename:          Whether or not to automatically rename matched functions in the kb. Defaults to False.
        :param binary:          The binary to analyze. Defaults to the project's main_object.
        :param cfg:             The CFG to use, if applicable. Defaults to None `project.cfg`, if it exists,
                                or None otherwise.
        :param use_sym:         Whether or not to include all functions in the binary's symbols in scanning
        :param use_kb:          Whether or not to include all non-SimProcedure, non-Syscall functions from the kb in
                                scanning. 
        :param use_cfg_nodes:   Whether or not to include all *unnamed* nodes in the CFG in scanning
        :param addrs:           A ``list`` of addresses to scan.
        :param exclude:         A ``list`` of node/function addresses to remove from the list of addresses generated by
                                other options. They are only relevant if they are a function's start address or, if
                                use_cfg_nodes==True, a node's address; they are not "avoided" during scanning.
        :param doscan:          Whether or not to immediately start the scan
        :param kwargs:          Params passed directly to child classes
        """
        self.rename         = rename
        self.binary         = binary if binary is not None else self.project.loader.main_object
        self.cfg            = cfg
        self.use_sym        = use_sym
        self.use_kb         = use_kb
        self.use_cfg_nodes  = use_cfg_nodes
        self.user_addrs     = addrs
        self.exclude_addrs  = exclude

        self.bs             = self.binary.binary_stream
        self.scanner        = None

        if cfg is None and use_cfg_nodes is True:
            if self.project is None:
                l.error('use_cfg_specified but there is no project and a CFG was not provided')
            elif not hasattr(self.project, 'cfg'):
                l.error('use_cfg_specified but the project has no CFG and a CFG was not provided')
            else:
                self.cfg = self.project.cfg

        try:
            ScanClass = registered_signature_scanners[method.lower()]
            self.scanner = ScanClass(addrlist=self._get_addrs(),
                                     bs=self.bs,
                                     rename=self.rename,
                                     kb=self.kb,
                                     binary=self.binary,
                                     offset=self.binary.mapped_base,
                                     **kwargs)
        except KeyError:
            l.error("Unknown signature scanner (%s). Registered scanners: %s", method, registered_signature_scanners.keys())
            raise
            
        if doscan:
            self.scan()

    @property
    def matches(self):
        if self.scanner is not None:
            return self.scanner.matches
        else:
            l.warn('There is no scanner, Neo.')
        
    @property
    def sym_func_addrs(self):
        """
        Returns a list of addresses: every function in the binary's symbols
        """
        if self.binary is None:
            return []

        return [k for k,v in self.binary.symbols_by_addr.items() if v.is_function is True]

    @property
    def kb_func_addrs(self):
        """
        Returns a list of addresses: every function in the KnowledgeBase excluding SimProcedures and SysCalls.
        """
        if self.kb is None:
            return []

        if not hasattr(self.kb, 'functions'):
            l.warn('No functions in KnowledgeBase. Try running a CFG.')
            return []

        return [k for k,v in self.kb.functions.items() if not v.is_syscall and not v.is_simprocedure]


    @property
    def cfg_unnamed_node_addrs(self):
        """
        Returns a list of addresses: every node in the CFG that is unnamed (not part of a function)
        """
        if self.cfg is None:
            return []
        return [f.addr for f in self.cfg.nodes() if f.name is None ]

    def _get_addrs(self):
        """
        Returns the complete, sorted list of all addresses to scan based on provided options
        """
        sym_addrs = []
        kb_addrs  = []
        cfg_addrs = []

        if self.use_sym is True:
            sym_addrs = self.sym_func_addrs
        if self.use_kb is True:
            kb_addrs = self.kb_func_addrs
        if self.use_cfg_nodes is True:
            cfg_addrs = self.cfg_unnamed_node_addrs

        return sorted(set(self.user_addrs + self.exclude_addrs + sym_addrs + kb_addrs + cfg_addrs) \
                    - set(self.exclude_addrs))

    def scan(self):
        """
        Initiates the scan and returns a list of any matches found.
        """
        if self.scanner is not None:
            self.scanner.scan()
        else:
            l.error('No scanner specified.')

    def __repr__(self):
        scanner = self.scanner if self.scanner is not None else self
        return '<%s Signature Scan Result at %#x>' % (scanner._name, id(scanner))

class SigScanBase(object):
    def __init__(self, addrlist, bs, rename=False, kb=None, binary=None, offset=0, **kwargs):
        """
        :param addrlist:    The addresses to scan
        :param bs:          The binary stream (``file``) object to scan
        :param rename:      Whether or not to automatically rename matched functions in the kb.
                            Defaults to False.
        :param kb:          The Angr KnowledgeBase from which to pull function addresses for scanning
                            and, if specified, in which to rename matched functions.
        :param binary:      The binary to analyze. Defaults to the project's main_object.
        :param offset:      Address offset, if the binary has been mapped into memory at an offset,
                            such as by Angr's CLE binary loader. Defaults to 0x0 in non-Project use
                            or to `binary.mapped_base` when used with an Angr Project.
        :param kwargs:      Various options for child classes
        """
        self.addrlist   = addrlist
        self.rename     = rename
        self.bs         = bs
        self.kb         = kb
        self.binary     = binary
        self.offset     = offset

        self.matches    = []

        def scan(self):
            l.error('This method must be overridden by a child class which implements scanning.')
            pass
            
class FlirtScan(SigScanBase):
    """
    .. |nampa| replace:: :mod:`nampa`
    A wrapper around nampa to provide FLIRT signature scanning. This class
    may either be used as part of an angr Project (through `SigScan`) or used
    independently by supplying arguments (in kwargs) as defined in __init__().

    If used as an Angr project, see `SigScan`. If used independently, note the
    various Keyword Arguments that must be provided.
    """
    def __init__(self, addrlist, bs, rename=False, kb=None, binary=None, offset=0, **kwargs):
        super(FlirtScan, self).__init__(addrlist=addrlist, bs=bs, rename=rename, kb=kb, binary=binary, offset=offset, **kwargs)
        """
        :param sigpath:     Path to a FLIRT signature file or a directory. If a directory, only
                            files ending with `.sig` are considered. Defaults to ``os.getcwd()``.
        :param callback:    A function nampa calls for every match. Must be ``callback(addr, func)``.
                            Defaults to ``FlirtScan._nampa_callback``. This is used internally and 
                            should only be specified if you wish to handle matches manually.

        :Example of non-Project Use:
        ```
        from angr.analyses.sigscan import FlirtScan
        bs = open('/home/user/program', 'rb')
        addrlist = [0x350, 0x493, 0x4ad, 0x4f7, 0x541]
        f = FlirtScan(addrlist=addrlist, bs=bs, rename=False, sigpath='/home/user/libc-2.22.sig')
        f.scan()
        print len(f.matches)
        ```
        """

        self.sigpath    = kwargs.get('sigpath', os.getcwd())
        self.callback   = kwargs.get('callback', self._nampa_callback)
        self.signatures = self._load_signatures(self.sigpath)


        # TODO: HACK for nampa
        # The callback from nampa has to be a static method since it only
        # passes its `func` instance and the address, so we need to keep
        # a reference to the currently-running FlirtScan instance. We should
        # probably just put in a PR to add the ability to pass a **kwargs
        # param and we can pass the instance there.
        FlirtScan._cur_instance = self

    #
    # Static vars
    #
    _cur_instance   = None
    _FUNCTION_TAIL_LENGTH = 0x100

    @staticmethod
    def _nampa_callback(addr, func):
        """
        The callback for nampa to call on every matched function
        """
        kb      = FlirtScan._cur_instance.kb
        binary  = FlirtScan._cur_instance.binary
        rename  = FlirtScan._cur_instance.rename

        match = Match(func, addr, kb, binary, rename)
        l.debug('Matched %s at %x', func.name, addr)
        FlirtScan._cur_instance.matches.append(match)

    def scan(self):
        self._match_addrs(self.addrlist, self.offset)
        FlirtScan._cur_instance = None

    def _load_signatures(self, sigpath):
        sigfiles = []
        if os.path.isfile(sigpath):
            sigfiles.append(sigpath)
        elif os.path.isdir(sigpath):
            sigfiles.extend([os.path.join(sigpath, f) for f in next(os.walk(sigpath))[2] if f.endswith('.sig')])

        signatures = []
        for sf in sigfiles:
            with open(sf, 'rb') as sigfile:
                signatures.append(nampa.parse_flirt_file(sigfile))

        return signatures

    def _match_addrs(self, addrlist, offset):
        for s in self.signatures:
            l.info("Scanning %d addresses for signatures in '%s'", len(addrlist), s.header.library_name)
            for addr in addrlist:
                start = addr ^ offset
                end = addr + 128 # TODO: HACK. Symbols give a size. KB functions do not. Need something here
                self.bs.seek(start, 0)
                buf = self.bs.read(end - start + FlirtScan._FUNCTION_TAIL_LENGTH)
                nampa.match_function(s, buf, start, self.callback)


register_analysis(SigScan, 'SigScan')

registered_signature_scanners = {}

def register_signature_scanner(cls, name):
    registered_signature_scanners[name] = cls
    
register_signature_scanner(FlirtScan, 'flirt')
