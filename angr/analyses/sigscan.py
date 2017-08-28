from . import Analysis, register_analysis
import nampa
import os
import logging
import operator

l = logging.getLogger('angr.analyses.sigscan')

class Match:
    """
    Defines a positive match, or 'find', from a signature scan
    """
    def __init__(self, funcaddr, kb, backend, flirtfunc):
        """
        :param funcaddr:    The address of the matched function
        :param kb:          The Angr KnowledgeBase containing functions
        :param backend:     The CLE backend containing symbols
        """
        self.funcaddr       = funcaddr + backend.mapped_base
        self.kb             = kb
        self.backend        = backend
        self.flirtfunc      = flirtfunc
        self.funcname       = flirtfunc.name


    @property
    def kb_func(self):
        if self.funcaddr in self.kb.functions:
            return self.kb.functions[self.funcaddr]
        return None



class SigScan(Analysis):
    """
    Angr Analysis base class for signature scanning. It provides default values to the signature scanners
    based on the current project, or as specified. If a CFG is not specified, a CFGFast will be generated
    and its KB will be used as the source of function addresses to scan.
    """
    def __init__(self, method, backend=None, cfg=None, exclude=[], doscan=True, **kwargs):
        """
        :param method:          The type of signature scan to do
        :param backend:         The CLE backend to analyze. Defaults to the project's main_object.
        :param cfg:             The CFG to use, if applicable. Defaults to None `project.cfg`, if it exists,
                                or None otherwise.
        :param addrs:           A ``list`` of addresses to scan.
        :param exclude:         A ``list`` of node/function addresses to remove from the list of addresses generated by
                                other options. They are only relevant if they are a function's start address or, if
                                use_cfg_nodes==True, a node's address; they are not "avoided" during scanning.
        :param doscan:          Whether or not to immediately start the scan
        :param kwargs:          Params passed directly to child classes
        """
        self.backend        = backend if backend is not None else self.project.loader.main_object
        self.cfg            = cfg
        #self.user_addrs     = addrs         # TODO: Maybe change to CFG nodes?
        self.exclude_addrs  = exclude

        self.bs             = self.backend.binary_stream
        self.scanner        = None

        if self.cfg is None:
            l.warn('No CFG provided. Generating CFGFast w/ any additional function_starts from addrs.')
            if self.project is None:
                l.error('There is no project and a CFG was not provided')
            self.cfg = self.project.analyses.CFGFast()
            l.warn('Using KB generated by CFG')
            self.kb = self.cfg.kb


        try:
            ScanClass = registered_signature_scanners[method.lower()]
            self.scanner = ScanClass(funclist=self._get_funcs(),
                                     bs=self.bs,
                                     kb=self.kb,
                                     cfg=self.cfg,
                                     backend=self.backend,
                                     offset=self.backend.mapped_base,
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
    def cfg_unnamed_node_addrs(self):
        """
        Returns a list of addresses: every node in the CFG that is unnamed (not part of a function)
        """
        if self.cfg is None:
            return []
        return [f.addr for f in self.cfg.nodes() if f.name is None ]

    def _get_funcs(self):
        # TODO: Remove excluded funcs
        kb_funcs = [v for k,v in self.kb.functions.items() if not v.is_syscall and not v.is_simprocedure ]#and v.name.startswith('sub_')]

        # Two functions in a given FLIRT module are only differentiated by offset, so we
        # must always find the lowest one first since the modules are checked in their
        # natural, lower-to-higher offset, order.
        allfuncs = sorted(kb_funcs, key=operator.attrgetter('addr'))
        l.debug(allfuncs)
        return allfuncs      

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
    def __init__(self, funclist, bs, cfg=None, kb=None, backend=None, offset=0, **kwargs):
        """
        :param bs:          The binary stream (``file``) object to scan
        :param kb:          The Angr KnowledgeBase from which to pull function addresses for scanning
                            and, if specified, in which to rename matched functions.
        :param backend:     The CLE backend to analyze. Defaults to the project's main_object.
        :param offset:      Address offset, if the binary has been mapped into memory at an offset,
                            such as by Angr's CLE binary loader. Defaults to 0x0 in non-Project use
                            or to `binary.mapped_base` when used with an Angr Project.
        :param kwargs:      Various options for child classes
        """
        self.funclist   = funclist
        self.bs         = bs
        self.cfg        = cfg
        self.kb         = kb
        self.backend    = backend
        self.offset     = offset

        self.matches    = {}

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
    def __init__(self, funclist, bs, cfg=None, kb=None, backend=None, offset=0, **kwargs):
        super(FlirtScan, self).__init__(funclist=funclist, bs=bs, cfg=cfg, kb=kb, backend=backend, offset=offset, **kwargs)
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
        f = FlirtScan(addrlist=addrlist, bs=bs, sigpath='/home/user/libc-2.22.sig')
        f.scan()
        print len(f.matches)
        ```
        """

        self.sigpath    = kwargs.get('sigpath', os.getcwd())
        self.callback   = kwargs.get('callback', self._nampa_callback)

        self.signatures = self._load_signatures(self.sigpath)
        self.created_kb_funcs = {}
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
    def _nampa_callback(addr, flirtfunc):
        """
        The callback for nampa to call on every matched function
        :param addr:    The offset of the function in the supplied buffer
        :param func:    A `nampa.FlirtFunction` object
        """
        fs      = FlirtScan._cur_instance
        offaddr = addr + flirtfunc.offset
        #refdby = flirtfunc.refd_by.name if flirtfunc.refd_by is not None else 'None'
        #l.debug('FIRSTPASSCALLBACK: %s [0x%04x] refd by %s', flirtfunc.name, addr, refdby)

        if flirtfunc.name in fs.matches:
            return False

        match = Match(offaddr, fs.kb, fs.backend, flirtfunc)
        kbf = match.kb_func
        if kbf is None:
            # TODO: HACK: Can't seem to create a CFG without a project, so we reach back to the project here
            fs.cfg.project.analyses.CFGFast(function_starts=[offaddr + match.backend.mapped_base])
            kbf = match.kb_func
            l.warn('CALLBACK: Created new KB function: %s', kbf.name)
            fs.created_kb_funcs[kbf.addr] = kbf
            if kbf is None:
                l.error('CALLBACK: Failed to create function in KB')

        l.debug('CALLBACK: %s KB function: %s', flirtfunc.name, kbf)
        kbf.name = flirtfunc.name
        fs.matches[flirtfunc.name] = match
        return True


    def scan(self):
        self._match_funcs(self.funclist, self.offset)
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


    def _match_funcs(self, funclist, offset):
        for s in self.signatures:
            l.info("Scanning %d funcs for signatures in '%s'", len(funclist), s.header.library_name)
            for func in funclist:
                l.debug('Checking %s', func.name)
                addrlist = func._addr_to_block_node.keys()
                #addrlist.remove(func.addr)  # If the ref functions were unrecognized, we need to find them first
                                             # without potentially erroneous matches for the function itself
                for addr in addrlist:
                    l.debug('Checking 0x%08x', addr)
                    start = addr - offset   # Removing the mapped_base
                    end = start + func.size
                    self.bs.seek(start, 0)
                    buf = self.bs.read(end - start + FlirtScan._FUNCTION_TAIL_LENGTH)

                    nampa.match_function(s, buf, start, self.callback)

            l.warn('Updating CFG...')
            self.cfg.project.analyses.CFGFast(function_starts=self.created_kb_funcs.keys())


register_analysis(SigScan, 'SigScan')

registered_signature_scanners = {}

def register_signature_scanner(cls, name):
    registered_signature_scanners[name] = cls

register_signature_scanner(FlirtScan, 'flirt')
