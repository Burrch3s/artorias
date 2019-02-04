# Settings that are configurable

# Directory to output scans reports to
SCAN_OUTPUT_DIR = 'core/outputs'

# File name and relative path to file
WORD_LIST = 'scanners/rockyou.txt'

# Arguments for datetime.now().strftime calls. Can be configured for finer or looser times logged
DATE_ARGS = '%m-%d_%H-%M-%S'

# Default ports for Web scans
WEB_PORTS = ('80', '443', '8080')

# Default ports for Auth scans w/ Hydra
AUTH_PORTS = ('22', '23', '80', '443')
