# ksf_stuff

A collection of small experimental scripts/libraries related to file format specifications from [kaitai_struct_formats](https://github.com/kaitai-io/kaitai_struct_formats).

## Disclaimer

I've uploaded this code here in the hope that someone else might find it useful. However, it is not very well tested or documented - it worked for my use cases, but I cannot guarantee that it will always work correctly. Because of this, none of the tools and libraries in this repo are available on PyPI.

All code in this repo is released under the [MIT License](./LICENSE). If you want to use it in your own projects or build something on top of it, please copy over the parts that you need.

## Structure

The structure of this repo mirrors that of kaitai_struct_formats, and usually each script/library corresponds to the KSF spec of the same name.

At the moment, all code in this repo is written in Python. The compiled specs are expected to be importable from a package named `ksf`. For example, the compiled version of `kaitai_struct_formats/serialization/php_serialized_value.ksy` is expected to be importable as `ksf.php_serialized_value`. The submodules of `ksf` are flat rather than following the directory structure of kaitai_struct_formats, because Kaitai Struct doesn't support proper namespaces yet.
