import argparse
import pathlib
import socket
import re
from collections import Counter


TITLE = "Flow Log Parser"
DESC = "Program that parses a file with flow log data to tags from a lookup file."
LOG_REGEX = re.compile(r"^(\d+) \d+ .+ [0-9|\.]+ [0-9|\.]+ \d+ (\d+) (\d+) \d+ \d+ \d+ \d+ (\w+) (\w+)$")
LOG_VERSION = "2"


def gen_protocol_mappings():
    """Generate mapping from protocol numbers (in lower case) to their names using socket lib."""

    mappings = {}

    for name, value in vars(socket).items():
        if name.startswith("IPPROTO_"):
            mappings[str(value)] = name[8:].lower()

    return mappings


def parse_lookup(path):
    """
    Load the lookup file at [path], returning contents in a dictionary. Rows with missing
    values are skipped.
    """

    lookup = {}

    with path.open("r") as lookup_file:
        for line in lookup_file:
            if len(split_line := line.strip().split(",")) != 3:
                continue

            dstport, protocol, tag = split_line
            lookup[f"{dstport},{protocol.lower()}"] = tag

    return lookup


def parse_log(path, lookup):
    """
    Parse each row of flow log file at [path] to tags using [lookup]. Rows with missing values are
    skipped.
    """

    with path.open("r") as log_file:
        tag_counts = Counter()
        port_protocol_counts = Counter()
        protocol_mappings = gen_protocol_mappings()

        for line in log_file:
            if not (line_match := LOG_REGEX.fullmatch(line.strip())):
                continue
            if line_match.group(1) != LOG_VERSION: # Check log version
                continue
            if not line_match.group(3) in protocol_mappings:
                continue
            if line_match.group(4) != "ACCEPT":
                continue
            if line_match.group(5) != "OK":
                continue

            _, dstport, protocol_num, _, _ = line_match.groups()
            key = f"{dstport},{protocol_mappings[protocol_num]}"

            port_protocol_counts[key] += 1

            if key in lookup:
                tag_counts[lookup[key]] += 1
            else:
                tag_counts["Untagged"] += 1

        return tag_counts, port_protocol_counts


def write_output(path, tag_counts, port_protocol_counts):
    """Write [tag_counts] and [port_protocol_counts] to output file at [path]."""

    with path.open("w") as output_file:
        output_file.write("Tag Counts:\nTag,Count\n")
        for tag, count in tag_counts.items():
            output_file.write(f"{tag},{count}\n")

        output_file.write("Port/Protocol Combination Counts:\nPort,Protocol,Count\n")
        for port_protocol, count in port_protocol_counts.items():
            output_file.write(f"{port_protocol},{count}\n")


def run(log_path, lookup_path, output_path):
    """Run program on parse file [log_path] with table from [lookup_path], outputting to [output_path]."""

    lookup = parse_lookup(lookup_path)
    tag_counts, port_protocol_counts = parse_log(log_path, lookup)
    write_output(output_path, tag_counts, port_protocol_counts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog = TITLE,
        description = DESC,
    )

    parser.add_argument("log_path", type=pathlib.Path)
    parser.add_argument("lookup_path", type=pathlib.Path)
    parser.add_argument("output_path", type=pathlib.Path)

    args = parser.parse_args()
    run(args.log_path, args.lookup_path, args.output_path)
    print(f"Wrote to {args.output_path.absolute()}")
