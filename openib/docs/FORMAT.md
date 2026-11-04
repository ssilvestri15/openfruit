# UIKit NIBArchive format used by OpenIB

OpenIB treats a modern UIKit NIB as four indexed tables preceded by a 50-byte header.

```text
magic[10] = "NIBArchive"
u32 formatVersion
u32 coderVersion
u32 objectCount
u32 objectOffset
u32 keyCount
u32 keyOffset
u32 valueCount
u32 valueOffset
u32 classCount
u32 classOffset
```

The object, key, and class tables use a UIKit-style VInt32 integer representation: seven payload bits per byte, least-significant group first, with bit 7 set on the final byte.

## Objects

Each object stores:

```text
vint classIndex
vint valueStart
vint valueCount
```

Object zero is the archive root.

## Values

Each value starts with a VInt32 key index and one type byte.

| Type | Meaning | Payload |
|---:|---|---|
| 0x00 | Int8 | 1 byte |
| 0x01 | Int16 | 2 LE bytes |
| 0x02 | Int32 | 4 LE bytes |
| 0x03 | Int64 | 8 LE bytes |
| 0x04 | false | none |
| 0x05 | true | none |
| 0x06 | Float | 4 LE bytes |
| 0x07 | Double | 8 LE bytes |
| 0x08 | Bytes | vint length + data |
| 0x09 | nil | none |
| 0x0A | Object reference | u32 LE object index |

## Classes

Each class record stores the class name length including the terminating zero, a VInt32 fallback-class count, fallback class indices as little-endian u32 values, and the zero-terminated UTF-8 class name.

## Foundation collections

`NSArray` and `NSDictionary` are represented as inlined NIB objects using `NSInlinedValue = true` followed by repeated `UINibEncoderEmptyKey` references. Dictionaries alternate key and value references.

This document describes OpenIB's current understanding and is intentionally treated as a compatibility model, not an Apple specification.
