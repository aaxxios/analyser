import argparse
from analyser import anal
import textwrap

epilog = textwrap.dedent("""
Author: axios ::
email: xxxjamesfoil@gmail.com""")
def main():
	parser = argparse.ArgumentParser(description="""
		Scan files for emails, ipv4 addreses, mac addresses and urls""", epilog=epilog)
	exclusive = parser.add_mutually_exclusive_group(required=True)
	exclusive.add_argument('-f', "--file",  metavar='<filename>', type=str, nargs='+', help='files to analyse\n')
	parser.add_argument('-o', "--output", dest='output', help="File to write output of analysis to. If not given, content will be written to stdout")
	exclusive.add_argument("-i", "--inline", dest="inline", nargs="+",)
	args = parser.parse_args()
	
	if args.inline:
		analysis = anal.Analyser([])
		analysis.scanString(" ".join(args.inline))
	else:
		analysis = anal.Analyser(args.file)
		analysis.summarize()
if __name__ == "__main__":
	main()
