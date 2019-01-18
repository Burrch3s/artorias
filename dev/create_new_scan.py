from string import Template
from argparse import ArgumentParser

from os import getcwd
import sys
sys.path.insert(0, getcwd())
from core.utils import file_to_class_name

def init_args() -> ArgumentParser:
    """
    Provide args to replace template values from dev/scan_template. Implement args to
    allow for easy scaling and not complicated manipulation of sys.argv.
    """
    parser = ArgumentParser(
        description="Use the template from dev/scan_template to create a new scan.")
    parser.add_argument(
        "-n",
        "--name",
        required=True,
        help="Name of the new scan to create and output to core/scans")

    return parser

def main() -> None:
    args = init_args().parse_args()
    template_args = {
        'SCAN_NAME': file_to_class_name(args.name),
    }

    with open('dev/scan_template', 'r') as temp:
        in_file = Template(temp.read())

    out_file = in_file.safe_substitute(template_args)

    with open('core/scans/{}.py'.format(args.name), 'w') as temp:
        temp.write(out_file)

if __name__ == "__main__":
    main()
