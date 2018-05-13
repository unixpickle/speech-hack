# speech-hack

This repository contains various notes and hacky scripts for extracting speech synthesis data from macOS's NSSpeechSynthesizer. The overarching goal is to get speech data that I can use to train a WaveNet model, but that may be too ambitious.

# Running

The Python scripts require Python 2 (unless you compiled your version of lldb to use Python 3). The scripts may need you to manually set your `PYTHONPATH`:

```
PYTHONPATH=$(lldb -P)
```
