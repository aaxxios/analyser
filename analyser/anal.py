import re
from typing import List, Union
from io import TextIOBase, BufferedIOBase
import os
from collections.abc import Sequence
from collections import namedtuple
from enum import Enum


class RegexEnum(Enum):
	MAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
	
	URL_REGEX = re.compile(r'(http[s]?://)?www(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
	
	IPV4_REGEX = re.compile(r"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(((\\8|\\16|\\24|))|:([1-9][0-9]*))?")
	MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})")


TERM_S = int(os.get_terminal_size().columns // 1.17)
details = namedtuple("details", "emails urls ipv4 macs")


class UnsupportedFile(Exception):
	"""this exceptuon is raised whrn trying to open unsupported files"""
	...


class Analyser:
	"""Analyser class, accepts a list containing file name or opened file
	 objects in text mode. The optional output_to if supplied should be a file name which analysis details
	 should be written to. If the file already exists, its contents will be
	 overridden. For quick testing of strings use the isValid* convenience
	 methods"""
	def __init__(self, files: List[Union[str, TextIOBase]], output_to=None) -> None:
		self._buffer = self._setbuffer(files)
		self.output = output_to
		self.emails = []
		self.macs = []
		self.ips = []
		self.urls = []
		self.processed = False
		
	def _validfile(self, name):
		"""check if name is a valid file"""
		if not os.path.exists(name):
			print("Skipping %s: File does not exist" % name)
			return 
		if os.path.isdir(name):
			print("Skipping %s: Directory" % name)
			return 
		return True
		
	def _setbuffer(self, buf):
		"""internal method responsible for prrpating files yo be read"""
		if isinstance(buf, Sequence) and not isinstance(buf, str):
			bufs = []
			for item in buf:
				if isinstance(item, BufferedIOBase):
					raise UnsupportedFile("%s is not a text file" % item)
				if isinstance(item, str):
					if self._validfile(item):
						f = open(item)
						bufs.append(f)
				elif isinstance(item, TextIOBase):
					item.seek(0)
					bufs.append(item)
			return bufs
		elif isinstance(buf, BufferedIOBase):
			raise UnsupportedFile("%s is not a text file"% s)
		elif isinstance(buf, str) and self._validfile(buf):
			buf = open(buf)
			return  [buf]
	
	def summarize(self, internal=False):
		if self.processed:
			return self.info()
		for file in self._buffer:
			try:
				while (text :=  file.read(100)) != "":
					mail = [match.group() for match in RegexEnum.MAIL_REGEX.value.finditer(text)]
					url = [match.group() for mmatch in RegexEnum.URL_REGEX.value.finditer(text)]
					ip = [match.group() for match in RegexEnum.IPV4_REGEX.value.finditer(text)]
					mac = [match.group() for match in RegexEnum.MAC_REGEX.value.finditer(text)]
					if mail:
						self.emails.extend(mail)
					if url:
						self.urls.extend(url)
					if ip:
						self.ips.extend(ip)
					if mac:
						self.macs.extend(mac)
			except Exception as e:
				print("Skipping %s: not a text file"% file.name)
				continue
			file.close()
		self.processed = True
		if internal:
			return details(self.emails, self.urls, self.ips, self.macs)
		self.info()
	
	def getSummary(self):
		return self.summarize(internal=True)

	def info(self):
		results = [self.emails, self.urls, self.macs, self.ips]
		if not any(results):
			print("No details Found😔😔😔!!!")
			return 
		if not self.output:
			msg = ["Mails Found", "URLs Found", "Mac Address Found", "IPs Found"]
			style = ["{:^{}}\n{:^{}}".format(i, TERM_S, "="*len(i), TERM_S) for i in msg]
			for i in range(len(results)):
				if not results[i]:
					continue
				self._styleprint(results[i], style[i])
			return 
		self.save()
	
	def _styleprint(self, lst, desc):
		print(desc)
		n = len(lst)
		j = 0
		while j < n:
			try:
				a, b = lst[j:j+2]
				print(f"{a:<30} {b}")
				j = j + 2
			except ValueError:
				print(lst[-1])
				break
	
	def _writer(self, msg, handle):
		n = len(msg)
		if n <= 2:
			handle.write(str(msg))
		j = 0
		while j < n:
			try:
				a, b = msg[j:j+2]
				handle.write(f"{a:<30} {b}\n")
				j = j + 2
			except ValueError:
				handle.write(msg[-1])
				break

	def scanString(self, string):
		f = False
		for regex in RegexEnum:
			if (match := regex.value.finditer(string)):
				name = regex.name[:regex.name.find("_")].title() + " Found"
				m = [m.group() for m in match]
				if m:
					adx = "="*len(name)
					desc = f"{name:^{TERM_S}}\n{adx:^{TERM_S}}"
					print()
					f = True
					self._styleprint(m, desc)
		if not f:
			print("\nNo details Found😔😔😔!!!")

	def save(self,):
		with open(self.output, "w") as out:
			if self.emails:
				out.write("\n\nEmails\n".center(TERM_S))
				self._writer(self.emails, out)
			if self.ips:
				out.write("\n\nIPs\n".center(TERM_S))
				self._writer(self.ips, out)
			if self.macs:
				out.write("\n\nMac Adresses:\n".center(TERM_S))
				self._writer(self.macs, out)
			if self.urls:
				out.write("\n\nURLs:\n".center(TERM_S))
				self._writer(self.urls, out)
			
			print("Details saved to %s 😎" % out.name)


def isValidEmail(text):
	return True if RegexEnum.MAIL_REGEX.value.search(text) else False
	
def isValidURL(text):
	return True if RegexEnum.URL_REGEX.value.search(text) else False
	
def isValidMAC(text):
	return True if RegexEnum.MAC_REGEX.value.search(text) else False
		
def isValidIP4(text):
	return True if RegexEnum.IPV4_REGEX.value.search(text) else False
