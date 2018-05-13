"""
Latch on to the speechsynthesisd process and dump its
logs.
"""

import fcntl
import os
from random import random
import sys
from threading import Thread

import lldb

TEMP_DIR = '(char *)[NSTemporaryDirectory() UTF8String]'
GEN_SAMPLES = 'MTBEPhraseProcessor::GenerateSamples'
MEOW_DEBUG = 'MTBEDebugFlags::sMEOWDebug'
STDERR_SYMBOL = '__stderrp'
MACINTALK_MODULE = 'MacinTalk'


def main(pid):
    """
    Setup log dumping and forward it to stdout.
    """
    stream = dump_logs_async(pid, log_fn=log)
    while True:
        print(stream.readline().strip())


def dump_logs_async(pid, log_fn=lambda x: None):
    """
    Setup the speechsynthesisd process to send logs to us.

    Args:
      pid: the process ID of speechsynthesisd.
      log_fn: a function to call with log messages.

    Returns:
      A file handle for reading logs.
    """
    debugger = lldb.SBDebugger.Create()
    listener = debugger.GetListener()
    target = debugger.CreateTarget('')
    error = lldb.SBError()
    process = target.AttachToProcessWithID(listener, pid, error)
    try_sb_error(error)

    log_fn('creating FIFO...')
    our_fifo, their_fifo = setup_log_fifo(stopped_thread(process))

    log_fn('creating breakpoint...')
    try_breakpoint(target.BreakpointCreateByName(GEN_SAMPLES))

    log_fn('finding MEOW symbol...')
    meow_sym = find_symbol(target, MEOW_DEBUG)

    log_fn('overwriting standard error...')
    replace_stderr(target, process, their_fifo)

    def manage_thread():
        try_sb_error(process.Continue())
        while True:
            # https://github.com/llvm-mirror/lldb/blob/master/examples/python/process_events.py
            event = lldb.SBEvent()
            if not listener.WaitForEvent(1, event):
                continue
            thread = stopped_thread(process)
            if not thread:
                continue
            try:
                sym_name = thread.GetFrameAtIndex(0).GetSymbol().GetName()
                if GEN_SAMPLES in sym_name:
                    enable_debugging(target, process, meow_sym)
            finally:
                try_sb_error(process.Continue())

    th = Thread(target=manage_thread)
    th.daemon = True
    th.start()
    return our_fifo


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
    frame.EvaluateExpression('(int)setvbuf(' + str(address) + ', 0, 0)')


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


def enable_debugging(target, process, meow_sym):
    """
    Enable "MEOW" debug logs.
    """
    error = lldb.SBError()
    addr = meow_sym.GetStartAddress()
    process.WriteMemory(addr.GetLoadAddress(target), '\x01', error)
    try_sb_error(error)


def replace_stderr(target, process, fifo_value):
    """
    Replace ___stderrp with a FILE* SBValue.

    Args:
      target: an SBTarget to change.
      fifo_value: an SBValue representing the result of an
        fopen() call.
    """
    for mod in target.module_iter():
        for sym in mod:
            if sym.GetName() == STDERR_SYMBOL:
                if sym.GetStartAddress().GetOffset() != 0:
                    addr = sym.GetStartAddress().GetLoadAddress(target)
                    error = lldb.SBError()
                    str_val = fifo_value.GetData().GetString(error, 0)
                    try_sb_error(error)
                    process.WriteMemory(addr, str_val, error)
                    try_sb_error(error)


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
