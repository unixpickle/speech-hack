"""
Create a dataset of audio files coupled with unit
alignments extracted from speechsynthesisd.
"""

import argparse
import json
import os
import subprocess

from daemon_logs import dump_logs_async


def main():
    args = arg_parser().parse_args()
    if not os.path.exists(args.out_dir):
        os.mkdir(args.out_dir)
    print('Hooking up to speechsynthesisd...')
    daemon_log = dump_logs_async(daemon_pid(), log_done_audio=True)
    with open(args.sentences, 'rt') as in_file:
        for i, line in enumerate(in_file):
            line = line.strip()
            if not line:
                continue
            process_sentence(os.path.join(args.out_dir, str(i)), line, daemon_log)


def process_sentence(out_path, sentence, daemon_log):
    """
    Create the data for a sentence.
    """
    wav_path = out_path + '.wav'
    child = subprocess.Popen(['say', '-o', wav_path, '--data-format=LEI16@22050', sentence])
    units = []
    while True:
        line = daemon_log.readline()
        if line.startswith('Unit'):
            unit_str = line.split()[1]
            num_samples = int(line.split()[3].split('>')[1].split('[')[0])
            units.append({'unit': unit_str, 'samples': num_samples})
        elif line.startswith('*** AUDIO CLOSED ***'):
            break
    child.wait()
    with open(out_path + '.json', 'w+') as meta_out:
        json.dump({'sentence': sentence, 'units': units}, meta_out, sort_keys=True, indent=2)


def daemon_pid():
    """
    Get the process ID of speechsynthesisd.
    """
    child = subprocess.Popen(['pgrep', 'com.apple.speech.speechsynthesisd'],
                             stdout=subprocess.PIPE)
    stdout, _ = child.communicate()
    return int(stdout.strip())


def arg_parser():
    """
    Create an argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('sentences', help='a file containing one sentence per line')
    parser.add_argument('out_dir', help='output directory')
    return parser


if __name__ == '__main__':
    main()
