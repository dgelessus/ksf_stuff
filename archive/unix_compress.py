import argparse
import collections.abc
import itertools
import logging
import os
import sys
import typing

from ksf.unix_compress import UnixCompress

logger = logging.getLogger(__name__)


class UnixCompressCodeIterator(collections.abc.Iterator):
	byte_iterator: typing.Iterator[int]
	code_length: int
	current_group: typing.Optional[bytes]
	current_byte: int
	current_bit: int
	
	def __init__(self, bytestr: typing.Iterable[int], code_length: int) -> None:
		super().__init__()
		
		self.byte_iterator = iter(bytestr)
		self.code_length = code_length
		self.current_group = None
		self.current_byte = 0
		self.current_bit = 0
	
	def __iter__(self) -> "UnixCompressCodeIterator":
		return self
	
	def _next_bit(self) -> int:
		if self.current_group is None:
			assert self.current_bit == 0
			assert self.current_byte == 0
			# Read code_length bytes from byte_iterator.
			self.current_group = bytes(itertools.islice(self.byte_iterator, self.code_length))
			if not self.current_group:
				# Stop once there are no more bytes.
				raise StopIteration()
		
		# Extract the bit at the current position.
		bit = bool(self.current_group[self.current_byte] & 1 << self.current_bit)
		
		# Move to next bit. If necessary, also move to next byte or group.
		if self.current_bit == 7:
			if self.current_byte == len(self.current_group) - 1:
				self.current_group = None
				self.current_byte = 0
			else:
				self.current_byte += 1
			self.current_bit = 0
		else:
			self.current_bit += 1
		
		return bit
	
	def __next__(self) -> int:
		code = 0
		for i in range(self.code_length):
			code |= self._next_bit() << i
		return code
	
	def discard_current_group(self) -> None:
		self.current_group = None
		self.current_byte = 0
		self.current_bit = 0

class UnixCompressDecompressor(collections.abc.Iterator):
	INITIAL_CODE_LENGTH: typing.ClassVar[int] = 9
	INITIAL_DECOMPRESSION_TABLE: typing.ClassVar[typing.Sequence[bytes]] = [bytes([i]) for i in range(256)]
	
	code_iterator: UnixCompressCodeIterator
	block_mode: bool
	max_code_length: int
	last_chunk: typing.Optional[bytes]
	decompression_table: typing.List[bytes]
	
	@classmethod
	def from_struct(cls, struct: UnixCompress) -> "UnixCompressDecompressor":
		return cls(struct.data, struct.block_mode, struct.max_bits)
	
	@classmethod
	def decompress_struct(cls, struct: UnixCompress) -> bytes:
		return b"".join(cls.from_struct(struct))
	
	def __init__(self, data: bytes, block_mode: bool, max_code_length: int) -> None:
		super().__init__()
		
		self.code_iterator = UnixCompressCodeIterator(data, type(self).INITIAL_CODE_LENGTH)
		self.block_mode = block_mode
		self.max_code_length = max_code_length
		self._reset_decompression_table()
	
	def _reset_decompression_table(self) -> None:
		self.code_iterator.code_length = type(self).INITIAL_CODE_LENGTH
		self.last_chunk = None
		self.decompression_table = list(type(self).INITIAL_DECOMPRESSION_TABLE)
		if self.block_mode:
			# Placeholder entry for the reset code (256).
			# This value should never actually be used!
			self.decompression_table += [b"<LZW decompression table reset>"]
	
	def __iter__(self) -> "UnixCompressDecompressor":
		return self
	
	def __next__(self) -> bytes:
		# Once code_iterator is exhausted, this will raise StopIteration.
		# The exception will propagate up through __next__ and also stop this iterator.
		code = next(self.code_iterator)
		logger.debug(f"Code: {code} ({code:>0{self.code_iterator.code_length}b})")
		
		if code == 256 and self.block_mode:
			logger.debug("-> reset decompression table")
			self._reset_decompression_table()
			self.code_iterator.discard_current_group()
			return b""
		else:
			if code == len(self.decompression_table):
				# Special case: if code is exactly one higher than the highest currently valid code, repeat the last chunk and add its first byte once more at the end.
				# This is known as the "KwKwK problem", because it occurs when the uncompressed data contains a sequence of the form KwKwK (where K is a byte and w is a byte sequence and Kw is already in the compression dictionary). For a proper explanation, see https://stackoverflow.com/q/42130786.
				logger.debug("KwKwK string (code is one past current end of table)")
				assert self.last_chunk is not None
				chunk = self.last_chunk + self.last_chunk[:1]
			else:
				chunk = self.decompression_table[code]
			
			logger.debug(f"-> {chunk}")
			
			# Create new codes only if we have a previous chunk and the maximum table size would not be reached.
			# (When the maximum code length is reached, the last slot in the table is never filled.)
			if self.last_chunk is not None and len(self.decompression_table) < (1 << self.max_code_length) - 1:
				new_chunk = self.last_chunk + chunk[:1]
				logger.debug(f"New table entry: {len(self.decompression_table)} -> {new_chunk}")
				self.decompression_table.append(new_chunk)
			
			if len(self.decompression_table) >= 1 << self.code_iterator.code_length:
				# All codes used for current code length, so increase code length by one bit.
				self.code_iterator.code_length += 1
				logger.debug(f"Code length increased to {self.code_iterator.code_length} bits")
				self.code_iterator.discard_current_group()
				assert self.code_iterator.code_length <= self.max_code_length
			
			self.last_chunk = chunk
			
			return chunk


COMPRESS_SUFFIX_MAP = {
	".taZ": ".tar",
	".Z": "",
}

def get_out_filename(in_filename: str) -> str:
	if in_filename == "-":
		return "-"
	else:
		for suffix_before, suffix_after in COMPRESS_SUFFIX_MAP.items():
			if in_filename.endswith(suffix_before) and in_filename != suffix_before:
				out_filename = f"{in_filename[:-len(suffix_before)]}{suffix_after}"
				return "./-" if out_filename == "-" else out_filename
		
		# No matching suffix found
		return f"{in_filename}.uncompressed"

def tabulate(vals):
	# From pfmoore on GitHub:
	# https://github.com/pypa/pip/issues/3651#issuecomment-216932564
	assert len(vals) > 0
	
	sizes = [0] * max(len(x) for x in vals)
	for row in vals:
		sizes = [max(s, len(str(c))) for s, c in itertools.zip_longest(sizes, row)]
	
	result = []
	for row in vals:
		display = " ".join(
			str(c).ljust(s) if c is not None else ''
			for s, c in itertools.zip_longest(sizes, row)
		)
		result.append(display)
	
	return result, sizes

def main():
	ap = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
	ap.add_argument("--help", action="help")
	ap.add_argument("-l", "--list", action="store_true", help="List contents of the compressed file instead of extracting it")
	ap.add_argument("-o", "--output-file", type=str, help="The output file name, or - for stdout (default: derived from input file name, or - if reading from stdin)")
	ap.add_argument("file", type=str, default="-", help="The file to decompress, or - for stdin (default: -)")
	
	args = ap.parse_args()
	
	in_filename = args.file
	out_filename = args.output_file
	
	if out_filename is None:
		out_filename = get_out_filename(in_filename)
	
	if in_filename == "-":
		in_stream = sys.stdin.buffer
	else:
		in_stream = open(in_filename, "rb")
	
	try:
		struct = UnixCompress.from_io(in_stream)
		
		if args.list:
			print(f"Contents of {in_filename}:")
			rows, widths = tabulate([
				["File name", "Compressed size", "Uncompressed size", "Block mode?", "Max. code bits"],
				[os.path.basename(out_filename), struct._io.size(), len(UnixCompressDecompressor.decompress_struct(struct)), struct.block_mode, struct.max_bits],
			])
			rows.insert(1, " ".join("-"*width for width in widths))
			for row in rows:
				print(row)
		else:
			if out_filename == "-":
				out_stream = sys.stdout.buffer
			else:
				out_stream = open(out_filename, "wb")
			
			try:
				for part in UnixCompressDecompressor.from_struct(struct):
					out_stream.write(part)
			finally:
				if out_filename != "-":
					out_stream.close()
	finally:
		if in_filename != "-":
			in_stream.close()


if __name__ == "__main__":
	main()
