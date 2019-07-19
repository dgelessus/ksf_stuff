import argparse
import itertools
import os
import sys
import typing

from ksf.unix_pack import UnixPack

def levels_from_struct(tree_struct: UnixPack.Tree) -> typing.List[typing.List[typing.Any]]:
	levels = []
	nonleaf_count = 1
	for i, level_struct in enumerate(tree_struct.levels):
		leaves_bytes = [bytes([byte]) for byte in level_struct.leaves]
		nonleaf_count = 2*nonleaf_count - len(level_struct.leaves)
		if i == len(tree_struct.levels) - 1:
			# On the last level, there should be no more non-leaf nodes.
			# The nonleaf_count is actually 1 though, because of the implicit EOF leaf node.
			assert nonleaf_count == 1
			levels.append(leaves_bytes + [b""])
		else:
			levels.append([None] * nonleaf_count + leaves_bytes)
	
	return levels

def tree_from_levels(levels: typing.List[typing.List[typing.Any]]) -> typing.List[typing.Any]:
	tree = []
	level_progress = [0] * len(levels)
	node_stack = [tree]
	while node_stack:
		next_node = levels[len(node_stack)-1][level_progress[len(node_stack)-1]]
		level_progress[len(node_stack)-1] += 1
		
		if next_node is None:
			new_nonleaf = []
			node_stack[-1].append(new_nonleaf)
			node_stack.append(new_nonleaf)
		else:
			node_stack[-1].append(next_node)
		
		while node_stack and len(node_stack[-1]) > 1:
			node_stack.pop()
	return tree

def iter_bits(bytestr: bytes) -> typing.Iterable[int]:
	for byte in bytestr:
		for i in reversed(range(8)):
			yield int(bool(byte & 1 << i))

def huffman_decode(coded: bytes, tree: typing.List[typing.Any]) -> typing.Iterable[bytes]:
	node = tree
	for bit in iter_bits(coded):
		node = node[bit]
		if isinstance(node, bytes):
			if node:
				yield node
				node = tree
			else:
				return


def decompress_struct_incremental(struct: UnixPack) -> typing.Iterable[bytes]:
	tree = tree_from_levels(levels_from_struct(struct.tree))
	yield from huffman_decode(struct.data, tree)

def decompress_struct(struct: UnixPack) -> bytes:
	return b"".join(decompress_struct_incremental(struct))


PACK_SUFFIX_MAP = {
	".taz": ".tar",
	".z": "",
}

def get_out_filename(in_filename: str) -> str:
	if in_filename == "-":
		return "-"
	else:
		for suffix_before, suffix_after in PACK_SUFFIX_MAP.items():
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
		struct = UnixPack.from_io(in_stream)
		
		if args.list:
			print(f"Contents of {in_filename}:")
			rows, widths = tabulate([
				["File name", "Compressed size", "Uncompressed size"],
				[os.path.basename(out_filename), struct._io.size(), struct.len_uncompressed],
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
				for part in decompress_struct_incremental(struct):
					out_stream.write(part)
			finally:
				if out_filename != "-":
					out_stream.close()
	finally:
		if in_filename != "-":
			in_stream.close()


if __name__ == "__main__":
	main()
