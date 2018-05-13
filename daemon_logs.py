"""
Latch on to speechsynthesisd and stream its logs.
"""

import fcntl
from functools import partial
import os
from random import random
import sys
from threading import Event, Thread

import lldb  # pylint: disable=E0401

TEMP_DIR = '(char *)[NSTemporaryDirectory() UTF8String]'
STDERR_SYMBOL = '__stderrp'
MACINTALK_MODULE = 'MacinTalk'

MEOW_DEBUG_HOOK = 'MTBEPhraseProcessor::GenerateSamples'
WORKER_DEBUG_HOOK = 'MTBEWorker::DebugLog'

MEOW_DEBUG_FLAG = 'MTBEDebugFlags::sMEOWDebug'
WORKER_DEBUG_FLAG = 'MTBEDebugFlags::sMTXDebug'

DONE_AUDIO_HOOK = 'MTBEAudioFileSoundOutput::Disengage'


def main(pid):
    """
    Setup log dumping and forward it to stdout.
    """
    log('Hooking up to daemon...')
    with LogHook(pid) as logs:
        log('Reading logs...')
        while True:
            print(logs.readline().strip())


class LogHook:
    """
    A context manager that yields a file handle of log
    messages from speechsynthesisd.
    """

    def __init__(self,
                 pid,
                 log_meow=True,
                 log_worker=False,
                 log_done_audio=False):
        """
        Configure a hook.

        Args:
          pid: the process ID of speechsynthesisd.
          log_meow: whether or not to capture MEOW logs.
          log_worker: whether or not to capture worker logs.
          log_done_audio: enable a special debug log that
            prints "*** AUDIO CLOSED **" when an output audio
            file is closed.
        """
        self.pid = pid
        self.log_meow = log_meow
        self.log_worker = log_worker
        self.log_done_audio = log_done_audio
        self._attached = None

    def __enter__(self):
        assert self._attached is None
        self._attached = _AttachedHook(self.pid, self.log_meow, self.log_worker,
                                       self.log_done_audio)
        return self._attached.our_fifo

    def __exit__(self, *args):
        self._attached.stop()
        self._attached = None


class _AttachedHook:
    """
    An attached debugging session.
    """

    def __init__(self, pid, log_meow, log_worker, log_done_audio):
        self.done_event = Event()

        self.debugger = lldb.SBDebugger.Create()
        self.listener = self.debugger.GetListener()
        self.target = self.debugger.CreateTarget('')
        error = lldb.SBError()
        self.process = self.target.AttachToProcessWithID(self.listener, pid, error)
        try_sb_error(error)

        self.our_fifo, self.their_fifo = setup_log_fifo(stopped_thread(self.process))

        if log_meow:
            try_breakpoint(self.target.BreakpointCreateByName(MEOW_DEBUG_HOOK))
        if log_worker:
            try_breakpoint(self.target.BreakpointCreateByName(WORKER_DEBUG_HOOK))
        if log_done_audio:
            try_breakpoint(self.target.BreakpointCreateByName(DONE_AUDIO_HOOK))

        self.meow_flag = find_symbol(self.target, MEOW_DEBUG_FLAG)
        self.worker_flag = find_symbol(self.target, WORKER_DEBUG_FLAG)
        self.restore_stderr = replace_stderr(self.target, self.process, self.their_fifo)

        try_sb_error(self.process.Continue())
        assert not self.done_event.is_set()
        self.bg_thread = Thread(target=self.poll_thread)
        self.bg_thread.start()

    def stop(self):
        self.done_event.set()
        self.bg_thread.join()
        self.process.Detach()

    def poll_thread(self):
        while not self.done_event.is_set():
            # https://github.com/llvm-mirror/lldb/blob/master/examples/python/process_events.py
            event = lldb.SBEvent()
            if not self.listener.WaitForEvent(1, event):
                self.restore_stderr()
                continue
            thread = stopped_thread(self.process)
            if not thread:
                continue
            try:
                sym_name = thread.GetFrameAtIndex(0).GetSymbol().GetName()
                if MEOW_DEBUG_HOOK in sym_name:
                    set_debug_flag(self.target, self.process, self.meow_flag)
                elif WORKER_DEBUG_HOOK in sym_name:
                    set_debug_flag(self.target, self.process, self.worker_flag)
                elif DONE_AUDIO_HOOK in sym_name:
                    write_log(thread, self.their_fifo, '*** AUDIO CLOSED ***')
            finally:
                try_sb_error(self.process.Continue())


def stopped_thread(process):
    """
    Get the first stopped thread.
    """
    for thread in process:
        if thread.GetStopReason() not in [0, lldb.eStopReasonNone]:
            return thread
    return None


def setup_log_fifo(thread):
    """
    Create a FIFO from the attached process to this one.

    Args:
      thread: an SBThread in the process.

    Returns:
      A tuple (our_fifo, their_fifo), where our_fifo is a
        file handle and their_fifo is an SBValue for the
        FILE* to the FIFO.
    """
    frame = thread.GetFrameAtIndex(0)
    temp_dir = frame.EvaluateExpression(TEMP_DIR).GetSummary()[1:-1]
    log_out_path = os.path.join(temp_dir, 'socket' + str(random()))
    os.mkfifo(log_out_path)

    our_fifo = os.open(log_out_path, os.O_RDONLY | os.O_NONBLOCK)
    flags = fcntl.fcntl(our_fifo, fcntl.F_GETFL)
    fcntl.fcntl(our_fifo, fcntl.F_SETFL, flags ^ os.O_NONBLOCK)
    our_fifo = os.fdopen(our_fifo, 'r')

    their_fifo = frame.EvaluateExpression('(void *)fopen("' + log_out_path + '", "w")')
    enable_line_buffering(frame, their_fifo)

    return our_fifo, their_fifo


def enable_line_buffering(frame, fifo_value):
    """
    Enable line buffering for a FILE* SBValue.
    """
    error = lldb.SBError()
    address = fifo_value.GetData().GetAddress(error, 0)
    try_sb_error(error)
    frame.EvaluateExpression('(int)setvbuf(' + str(address) + ', 0, 1, 512)')


def write_log(thread, fifo_value, message):
    """
    Write a log message on behalf of the process.

    Args:
      thread: a stopped SBThread.
      fifo_value: the SBValue of the FILE*.
      message: the message to log. Should not contain
        backslashes or quotation marks.
    """
    assert '\\' not in message and '"' not in message, 'log messages are not escaped'
    frame = thread.GetFrameAtIndex(0)
    error = lldb.SBError()
    address = fifo_value.GetData().GetAddress(error, 0)
    try_sb_error(error)
    code = '(int)fprintf((void *)' + str(address) + ', (char *)"' + message + '\\n")'
    frame.EvaluateExpression(code)


def find_symbol(target, name, module=MACINTALK_MODULE):
    """
    Find an SBSymbol by the given name.
    """
    for mod in target.module_iter():
        if module and module != mod.GetFileSpec().GetFilename():
            continue
        for sym in mod:
            if sym.GetName() == name:
                return sym
    raise RuntimeError('symbol not found: ' + name)


def set_debug_flag(target, process, flag_sym):
    """
    Enable a debug flag.
    """
    error = lldb.SBError()
    addr = flag_sym.GetStartAddress()
    process.WriteMemory(addr.GetLoadAddress(target), '\x01', error)
    try_sb_error(error)


def replace_stderr(target, process, fifo_value):
    """
    Replace ___stderrp with a FILE* SBValue.

    Args:
      target: an SBTarget to change.
      fifo_value: an SBValue representing the result of an
        fopen() call.

    Returns:
      A function to restore the old values.
    """
    restore_fns = []
    for mod in target.module_iter():
        for sym in mod:
            if sym.GetName() == STDERR_SYMBOL:
                if sym.GetStartAddress().GetOffset() != 0:
                    addr = sym.GetStartAddress().GetLoadAddress(target)
                    error = lldb.SBError()
                    str_val = fifo_value.GetData().GetString(error, 0)
                    try_sb_error(error)
                    old_value = process.ReadMemory(addr, len(str_val), error)
                    try_sb_error(error)
                    process.WriteMemory(addr, str_val, error)
                    try_sb_error(error)
                    restore_fns.append(partial(process.WriteMemory, addr, old_value, error))
    return lambda: [f() for f in restore_fns]


def log(msg):
    sys.stderr.write(msg + '\n')


def try_sb_error(err):
    if err.fail:
        raise RuntimeError(err.GetCString())


def try_breakpoint(bp):
    if bp.GetNumLocations() != 1:
        raise RuntimeError('could not set breakpoint')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: dump_meow_logs.py <pid>\n')
        sys.exit(1)
    main(int(sys.argv[1]))
