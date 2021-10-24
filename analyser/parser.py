import argparse
from analyser import anal


def main():
	parser = argparse.ArgumentParser(description="""
		Scan files for emails, ipv4 addreses, mac addresses and urls""")
	exclusive = parser.add_mutually_exclusive_group(required=True)
	exclusive.add_argument('-f', "--file",  metavar='<filename>', type=str, nargs='+', help='files to analyse')
	parser.add_argument('-o', "--output", dest='output')
	exclusive.add_argument("-i", "--inline", dest="inline", type=str, nargs="+")
	args = parser.parse_args()
	
	if args.inline:
		analysis = anal.Analyser([])
		analysis.scanString(" ".join(args.inline))
	else:
		analysis = anal.Analyser(args.file)
		analysis.summarize()
if __name__ == "__main__":
	main()
