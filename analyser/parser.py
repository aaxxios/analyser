import argparse
from analyser import anal


def main():
	parser = argparse.ArgumentParser(description="""
		Scan files for emails, ipv4 addreses, mac addresses and urls""")
	parser.add_argument('file',  metavar='f', type=str, nargs='+', help='files to analyse')
	parser.add_argument('-o', "--output", dest='output')
	args = parser.parse_args()
	analysis = anal.Analyser(args.file, args.output)
	analysis.summarize()
if __name__ == "__main__":
	main()
