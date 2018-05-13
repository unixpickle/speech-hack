"""
Latch on to the speechsynthesisd process and dump its
logs.
"""

import os
from random import random
import sys
from threading import Thread
from time import sleep

import lldb

TEMP_DIR = '(char *)[NSTemporaryDirectory() UTF8String]'
GEN_SAMPLES = 'MTBEPhraseProcessor::GenerateSamples'
DEMI_DUMP = 'Demi::Dump(__sFILE*)'
MEOW_DEBUG = 'MTBEDebugFlags::sMEOWDebug'


def setup_log_dumping(pid):
    """
    Setup the process `pid` to dump it's "MEOW" logs.
    """
    debugger = lldb.SBDebugger.Create()
    listener = debugger.GetListener()
    target = debugger.CreateTarget('')
    error = lldb.SBError()
    process = target.AttachToProcessWithID(listener, pid, error)
    try_sb_error(error)

    log('creating FIFO...')
    our_fifo, their_fifo = setup_log_fifo(stopped_thread(process))
    log('creating breakpoints...')
    try_breakpoint(target.BreakpointCreateByName(DEMI_DUMP))
    try_breakpoint(target.BreakpointCreateByName(GEN_SAMPLES))
    log('finding MEOW symbol...')
    meow_sym = find_meow_sym(target)

    echo_from_fifo(our_fifo)

    try_sb_error(process.Continue())
    log('waiting for breakpoint...')
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
            elif DEMI_DUMP in sym_name:
                swap_out_stderr(thread, their_fifo)
            else:
                log('unexpected stop symbol: ' + sym_name)
        finally:
            try_sb_error(process.Continue())


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

    our_fifo = []

    def open_ours():
        our_fifo.append(open(log_out_path, 'r'))

    # Major hack to get around the fact that we're using
    # FIFOs in totally the wrong way.
    th = Thread(target=open_ours)
    th.daemon = True
    th.start()
    sleep(0.5)

    their_fifo = frame.EvaluateExpression('(void *)fopen("' + log_out_path + '", "w")')

    # Enable line buffering.
    error = lldb.SBError()
    address = their_fifo.GetData().GetAddress(error, 0)
    try_sb_error(error)
    frame.EvaluateExpression('(int)setvbuf(' + str(address) + ', 0, 0)')

    th.join()
    return our_fifo[0], their_fifo


def echo_from_fifo(our_fifo):
    """
    Run a background thread that echos our_fifo to stdout.
    """
    def echo_thread():
        while True:
            print(our_fifo.readline().strip())
    Thread(target=echo_thread).start()


def find_meow_sym(target):
    for mod in target.module_iter():
        for sym in mod:
            if sym.GetName() == MEOW_DEBUG:
                return sym
    raise RuntimeError('no symbol found: ' + MEOW_DEBUG)


def enable_debugging(target, process, meow_sym):
    """
    Enable MEOW debugging.
    """
    error = lldb.SBError()
    addr = meow_sym.GetStartAddress()
    process.WriteMemory(addr.GetLoadAddress(target), '\x01', error)
    try_sb_error(error)


def swap_out_stderr(thread, their_fifo):
    """
    Replace the argument to Demi::Dump() with our FIFO.
    """
    frame = thread.GetFrameAtIndex(0)
    reg = frame.FindRegister('rsi')
    error = lldb.SBError()
    reg.SetData(their_fifo.GetData(), error)
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
    setup_log_dumping(int(sys.argv[1]))
