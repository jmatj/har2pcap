import json
import blocks
import datetime


def parse_har(url):
    with open(url) as json_file:
        return json.load(json_file)['log']


def build_blocks(har):
    """Return a list of HTTP blocks"""
    blocks = []
    for entry in har['entries']:
        start_time = datetime.datetime.strptime(
            entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
        timestamp = start_time * 1e6 + int(entry['time'] * 1e3)
        request = entry['request']
        response = entry['response']
        # TODO: Build http-packet from request and response
    return blocks

if __name__ == "__main__":
    har = parse_har('../example.org.har')
    http_blocks = build_blocks(har)
