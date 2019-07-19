import collections
import enum

from ksf.php_serialized_value import PhpSerializedValue

PROPERTY_NAME_ENCODING = "utf-8"

class Php6String(bytes):
	def __repr__(self):
		return f"{type(self).__module__}.{type(self).__qualname__}({super().__repr__()})"

class PhpObject(object):
	def __init__(self, class_name, properties=None):
		super().__init__()
		
		self.class_name = class_name
		self.properties = collections.OrderedDict()
		if properties is not None:
			self.properties.update(properties)
	
	def __getattr__(self, name):
		try:
			return self.properties[name.encode(PROPERTY_NAME_ENCODING)]
		except (KeyError, UnicodeEncodeError):
			raise AttributeError(name)
	
	def __eq__(self, other):
		return type(self) == type(other) and self.class_name == other.class_name and self.properties == other.properties
	
	def __ne__(self, other):
		return not self == other
	
	def __repr__(self):
		return f"{type(self).__module__}.{type(self).__qualname__}({self.class_name!r}, {self.properties!r})"

class CustomSerializedObject(object):
	def __init__(self, class_name, data):
		super().__init__()
		
		self.class_name = class_name
		self.data = data
	
	def __eq__(self, other):
		return type(self) == type(other) and self.class_name == other.class_name and self.data == other.data
	
	def __ne__(self, other):
		return not self == other
	
	def __repr__(self):
		return f"{type(self).__module__}.{type(self).__qualname__}({self.class_name!r}, {self.data!r})"

class Reference(object):
	class Kind(enum.Enum):
		variable = enum.auto()
		object = enum.auto()
	
	def __init__(self, kind, number):
		super().__init__()
		
		self.kind = kind
		self.number = number
	
	def __eq__(self, other):
		return type(self) == type(other) and self.kind == other.kind and self.number == other.number
	
	def __ne__(self, other):
		return not self == other
	
	def __repr__(self):
		return f"{type(self).__module__}.{type(self).__qualname__}({self.kind!s}, {self.number!r})"

def deserialize_ksy_value(ksy_value):
	if ksy_value.type == PhpSerializedValue.ValueType.null:
		return None
	elif ksy_value.type in (PhpSerializedValue.ValueType.bool, PhpSerializedValue.ValueType.int, PhpSerializedValue.ValueType.string):
		return ksy_value.contents.value
	elif ksy_value.type == PhpSerializedValue.ValueType.float:
		return float(ksy_value.contents.value_dec)
	elif ksy_value.type == PhpSerializedValue.ValueType.php_6_string:
		return Php6String(ksy_value.contents.value)
	elif ksy_value.type == PhpSerializedValue.ValueType.array:
		od = collections.OrderedDict()
		
		for entry in ksy_value.contents.elements.entries:
			if entry.key.type not in (PhpSerializedValue.ValueType.int, PhpSerializedValue.ValueType.string):
				raise TypeError(f"Array keys must be of type int or string, not {entry.key.type}")
			py_key = deserialize_ksy_value(entry.key)
			if py_key in od:
				raise ValueError(f"Duplicate key: {py_key!r}")
			py_value = deserialize_ksy_value(entry.value)
			od[py_key] = py_value
		
		return od
	elif ksy_value.type in (PhpSerializedValue.ValueType.object, PhpSerializedValue.ValueType.php_3_object):
		if ksy_value.type == PhpSerializedValue.ValueType.php_3_object:
			obj = PhpObject(None)
		else:
			obj = PhpObject(ksy_value.contents.class_name.data)
		
		for entry in ksy_value.contents.properties.entries:
			if entry.key.type != PhpSerializedValue.ValueType.string:
				raise TypeError(f"Object property names must be of type string, not {entry.key.type}")
			py_key = deserialize_ksy_value(entry.key)
			if py_key in obj.properties:
				raise ValueError(f"Duplicate key: {py_key!r}")
			py_value = deserialize_ksy_value(entry.value)
			obj.properties[py_key] = py_value
		
		return obj
	elif ksy_value.type == PhpSerializedValue.ValueType.custom_serialized_object:
		return CustomSerializedObject(ksy_value.contents.class_name.data, ksy_value.contents.data)
	elif ksy_value.type == PhpSerializedValue.ValueType.variable_reference:
		return Reference(Reference.Kind.variable, ksy_value.contents.value)
	elif ksy_value.type == PhpSerializedValue.ValueType.object_reference:
		return Reference(Reference.Kind.object, ksy_value.contents.value)
	else:
		raise NotImplementedError(f"Unhandled value type {ksy_value.type}")

def deserialize_bytes(data):
	return deserialize_ksy_value(PhpSerializedValue.from_bytes(data))

def deserialize_stream(stream):
	return deserialize_ksy_value(PhpSerializedValue.from_io(stream))

def resolve_references_internal(obj, numbered_objects):
	if isinstance(obj, (collections.Mapping, PhpObject)):
		if isinstance(obj, PhpObject):
			mapping = obj.properties
		else:
			mapping = obj
		
		for key, val in mapping.items():
			if isinstance(val, Reference):
				new_val = numbered_objects[val.number]
			else:
				new_val = val
			numbered_objects.append(new_val)
			resolve_references_internal(val, numbered_objects)
			mapping[key] = new_val

def resolve_references(obj):
	numbered_objects = [None, obj]
	resolve_references_internal(obj, numbered_objects)
	return numbered_objects
