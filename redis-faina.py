#! /usr/bin/env python
import argparse
import sys
from collections import defaultdict
import re

# Prefix regex to extract timestamp, db, and client info
# Redis 2.4 format: 1339518083.107412 (db 0) "GET" "key1"
prefix_re_24 = re.compile(
    r'^(?P<timestamp>[\d.]+)\s(?:\(db\s(?P<db>\d+)\)\s)?'
)

# Redis 2.6+ format: 1339518083.107412 [0 127.0.0.1:6379] "GET" "key1"
prefix_re_26 = re.compile(
    r'^(?P<timestamp>[\d.]+)\s\[(?P<db>\d+)\s(?P<client>\d+\.\d+\.\d+\.\d+:\d+)]\s'
)

# Universal quoted argument extraction regex (correctly handles escaped quotes)
args_re = re.compile(r'"((?:[^"\\]|\\.)*)"')

# Redis hashtag extraction regex: matches {tag} at any position in the key
hashtag_re = re.compile(r'\{([^}]+)\}')

# Commands that have no key argument
NO_KEY_COMMANDS = frozenset({
    'SELECT', 'AUTH', 'PING', 'INFO', 'CONFIG', 'CLUSTER',
    'CLIENT', 'SUBSCRIBE', 'UNSUBSCRIBE', 'PSUBSCRIBE',
    'PUNSUBSCRIBE', 'DBSIZE', 'FLUSHDB', 'FLUSHALL',
    'RANDOMKEY', 'DEBUG', 'SLOWLOG', 'MONITOR', 'QUIT',
    'SAVE', 'BGSAVE', 'BGREWRITEAOF', 'TIME', 'COMMAND',
    'MULTI', 'EXEC', 'DISCARD', 'SCRIPT', 'WAIT', 'SWAPDB',
    'RESET', 'HELLO', 'LATENCY',
})

# Commands where all arguments are keys (e.g., DEL key1 key2 key3)
ALL_KEYS_COMMANDS = frozenset({
    'DEL', 'UNLINK', 'MGET', 'SUNION', 'SINTER', 'SDIFF',
    'WATCH', 'EXISTS',
})

# Commands where keys are at alternating positions (e.g., MSET key1 val1 key2 val2)
ALTERNATE_KEY_COMMANDS = frozenset({
    'MSET', 'MSETNX',
})

# Commands where the first two arguments are both keys
TWO_KEYS_COMMANDS = frozenset({
    'RENAME', 'RENAMENX', 'RPOPLPUSH', 'BRPOPLPUSH',
    'LMOVE', 'BLMOVE', 'SMOVE', 'COPY',
})

# Store commands: dest key + numkeys + source keys
# e.g., ZUNIONSTORE dest numkeys key1 key2
STORE_COMMANDS = frozenset({
    'ZUNIONSTORE', 'ZINTERSTORE', 'SUNIONSTORE',
    'SINTERSTORE', 'SDIFFSTORE',
})

# EVAL/EVALSHA: script/sha, numkeys, key1, key2, ..., arg1, arg2, ...
EVAL_COMMANDS = frozenset({
    'EVAL', 'EVALSHA',
})

# BLPOP/BRPOP: key1 key2 ... timeout (last arg is timeout, rest are keys)
BLOCKING_LIST_COMMANDS = frozenset({
    'BLPOP', 'BRPOP', 'BZPOPMIN', 'BZPOPMAX',
})

# XREAD/XREADGROUP: complex syntax, extract keys after STREAMS keyword
XREAD_COMMANDS = frozenset({
    'XREAD', 'XREADGROUP',
})

# OBJECT subcommand key
OBJECT_SUBCOMMAND = frozenset({
    'OBJECT',
})

# SORT key ... [STORE dest]
SORT_COMMANDS = frozenset({
    'SORT', 'SORT_RO',
})


def extract_keys(command, args):
    """Extract all keys from command arguments based on command type."""
    cmd = command.upper()

    if cmd in NO_KEY_COMMANDS:
        return []

    if cmd in ALL_KEYS_COMMANDS:
        return list(args)

    if cmd in ALTERNATE_KEY_COMMANDS:
        # MSET key1 val1 key2 val2 -> keys at even indices
        return args[::2]

    if cmd in TWO_KEYS_COMMANDS:
        return args[:2] if len(args) >= 2 else list(args)

    if cmd in STORE_COMMANDS:
        # dest numkeys key1 key2 ...
        keys = []
        if len(args) >= 1:
            keys.append(args[0])  # dest key
        if len(args) >= 2:
            try:
                numkeys = int(args[1])
                keys.extend(args[2:2 + numkeys])
            except (ValueError, IndexError):
                pass
        return keys

    if cmd in EVAL_COMMANDS:
        # EVAL script numkeys key1 key2 ... arg1 arg2 ...
        if len(args) >= 2:
            try:
                numkeys = int(args[1])
                return list(args[2:2 + numkeys])
            except (ValueError, IndexError):
                return []
        return []

    if cmd in BLOCKING_LIST_COMMANDS:
        # BLPOP key1 key2 ... timeout -> all args except the last are keys
        if len(args) > 1:
            return list(args[:-1])
        return list(args)

    if cmd in XREAD_COMMANDS:
        # XREAD [COUNT count] [BLOCK ms] STREAMS key1 key2 ... id1 id2 ...
        try:
            streams_idx = [a.upper() for a in args].index('STREAMS')
            remaining = args[streams_idx + 1:]
            # After STREAMS, first half are keys, second half are IDs
            num_keys = len(remaining) // 2
            return list(remaining[:num_keys])
        except (ValueError, IndexError):
            return []

    if cmd in OBJECT_SUBCOMMAND:
        # OBJECT subcommand key
        return args[1:2] if len(args) >= 2 else []

    if cmd in SORT_COMMANDS:
        # SORT key [BY pattern] [LIMIT offset count] [GET pattern ...] [ASC|DESC] [ALPHA] [STORE dest]
        keys = args[:1] if args else []
        # Also extract STORE destination if present
        try:
            store_idx = [a.upper() for a in args].index('STORE')
            if store_idx + 1 < len(args):
                keys.append(args[store_idx + 1])
        except ValueError:
            pass
        return keys

    # Default: first argument is the key (covers the vast majority of commands)
    return args[:1] if args else []


def parse_entry(line, prefix_re):
    """Parse a MONITOR output line into a structured entry dict.

    Returns None if the line cannot be parsed.
    """
    prefix_match = prefix_re.match(line)
    if not prefix_match:
        return None

    entry = prefix_match.groupdict()
    # Extract the remainder after the prefix
    remainder = line[prefix_match.end():]

    # Extract all quoted arguments from the remainder
    quoted_args = args_re.findall(remainder)
    if not quoted_args:
        return None

    command = quoted_args[0]
    all_args = quoted_args[1:]

    # Unescape any escaped characters in args (e.g., \" -> ")
    all_args = [a.replace('\\"', '"').replace('\\\\', '\\') for a in all_args]

    keys = extract_keys(command, all_args)

    entry['command'] = command.upper()
    entry['keys'] = keys
    entry['all_args'] = all_args
    return entry


class StatCounter(object):

    def __init__(self, prefix_delim=':', redis_version=2.6, top_n=8):
        self.line_count = 0
        self.skipped_lines = 0
        self.commands = defaultdict(int)
        self.keys = defaultdict(int)
        self.prefixes = defaultdict(int)
        self.hashtags = defaultdict(int)
        self.times = []
        self._cached_sorts = {}
        self.start_ts = None
        self.last_ts = None
        self.last_entry = None
        self.prefix_delim = prefix_delim
        self.redis_version = redis_version
        self.top_n = top_n
        self.prefix_re = prefix_re_24 if self.redis_version < 2.5 else prefix_re_26

    def _record_duration(self, entry):
        ts = float(entry['timestamp']) * 1000 * 1000 # microseconds
        if not self.start_ts:
            self.start_ts = ts
            self.last_ts = ts
        duration = ts - self.last_ts
        if self.redis_version < 2.5:
            cur_entry = entry
        else:
            cur_entry = self.last_entry
            self.last_entry = entry
        if duration and cur_entry:
            self.times.append((duration, cur_entry))
        self.last_ts = ts

    def _record_command(self, entry):
        self.commands[entry['command']] += 1

    def _record_key(self, key):
        self.keys[key] += 1
        parts = key.split(self.prefix_delim)
        if len(parts) > 1:
            self.prefixes[parts[0]] += 1
        # Extract Redis cluster hashtag {tag} from the key
        match = hashtag_re.search(key)
        if match:
            self.hashtags[match.group(1)] += 1

    @staticmethod
    def _reformat_entry(entry):
        max_args_to_show = 5
        output = '"%s"' % entry['command']
        all_args = entry['all_args']
        if all_args:
            # Show up to max_args_to_show arguments (formatted with quotes)
            display_args = ['"%s"' % a for a in all_args[:max_args_to_show]]
            ellipses = ' ...' if len(all_args) > max_args_to_show else ''
            output += ' %s%s' % (' '.join(display_args), ellipses)
        return output


    def _get_or_sort_list(self, ls):
        key = id(ls)
        if key not in self._cached_sorts:
            sorted_items = sorted(ls, key=lambda x: x[0])
            self._cached_sorts[key] = sorted_items
        return self._cached_sorts[key]

    def _time_stats(self, times):
        sorted_times = self._get_or_sort_list(times)
        num_times = len(sorted_times)
        percent_50 = sorted_times[int(num_times / 2)][0]
        percent_75 = sorted_times[int(num_times * .75)][0]
        percent_90 = sorted_times[int(num_times * .90)][0]
        percent_99 = sorted_times[int(num_times * .99)][0]
        return (("Median", percent_50),
                ("75%", percent_75),
                ("90%", percent_90),
                ("99%", percent_99))

    def _heaviest_commands(self, times):
        times_by_command = defaultdict(int)
        for time, entry in times:
            times_by_command[entry['command']] += time
        return self._top_n(times_by_command)

    def _slowest_commands(self, times, n=None):
        if n is None:
            n = self.top_n
        sorted_times = self._get_or_sort_list(times)
        slowest_commands = reversed(sorted_times[-n:])
        printable_commands = [(str(time), self._reformat_entry(entry)) \
                              for time, entry in slowest_commands]
        return printable_commands

    def _general_stats(self):
        total_time = (self.last_ts - self.start_ts) / (1000*1000)
        return (
            ("Lines Processed", self.line_count),
            ("Commands/Sec", '%.2f' % (self.line_count / total_time))
        )

    def process_entry(self, entry):
        self._record_duration(entry)
        self._record_command(entry)
        for key in entry['keys']:
            self._record_key(key)

    def _top_n(self, stat, n=None):
        if n is None:
            n = self.top_n
        sorted_items = sorted(stat.items(), key = lambda x: x[1], reverse = True)
        return sorted_items[:n]

    def _pretty_print(self, result, title, percentages=False):
        print(title)
        print('=' * 40)
        if not result:
            print('n/a\n')
            return

        display_keys = [('""' if x[0] == '' else x[0]) for x in result]
        max_key_len = max((len(dk) for dk in display_keys))
        max_val_len = max((len(str(x[1])) for x in result))
        for (key, val), display_key in zip(result, display_keys):
            key_padding = max(max_key_len - len(display_key), 0) * ' '
            if percentages:
                val_padding = max(max_val_len - len(str(val)), 0) * ' '
                val = '%s%s\t(%.2f%%)' % (val, val_padding, (float(val) / self.line_count) * 100)
            print('%s%s\t%s' % (display_key, key_padding, val))
        print()


    def print_stats(self):
        self._pretty_print(self._general_stats(), 'Overall Stats')
        self._pretty_print(self._top_n(self.prefixes), 'Top Prefixes', percentages = True)
        self._pretty_print(self._top_n(self.hashtags), 'Top Hashtags', percentages = True)
        self._pretty_print(self._top_n(self.keys), 'Top Keys', percentages = True)
        self._pretty_print(self._top_n(self.commands), 'Top Commands', percentages = True)
        self._pretty_print(self._time_stats(self.times), 'Command Time (microsecs)')
        self._pretty_print(self._heaviest_commands(self.times), 'Heaviest Commands (microsecs)')
        self._pretty_print(self._slowest_commands(self.times), 'Slowest Calls')

    def process_input(self, input):
        for line in input:
            self.line_count += 1
            line = line.strip()
            entry = parse_entry(line, self.prefix_re)
            if not entry:
                if line != "OK":
                    self.skipped_lines += 1
                continue
            self.process_entry(entry)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'input',
        type = argparse.FileType('r'),
        default = sys.stdin,
        nargs = '?',
        help = "File to parse; will read from stdin otherwise")
    parser.add_argument(
        '--prefix-delimiter',
        type = str,
        default = ':',
        help = "String to split on for delimiting prefix and rest of key",
        required = False)
    parser.add_argument(
        '--redis-version',
        type = float,
        default = 2.6,
        help = "Version of the redis server being monitored",
        required = False)
    parser.add_argument(
        '--top-n',
        type = int,
        default = 8,
        help = "Number of top entries to show in each stats section",
        required = False)
    args = parser.parse_args()
    counter = StatCounter(prefix_delim = args.prefix_delimiter, redis_version = args.redis_version, top_n = args.top_n)
    counter.process_input(args.input)
    counter.print_stats()
