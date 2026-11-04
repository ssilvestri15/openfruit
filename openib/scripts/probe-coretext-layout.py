"""Diagnostic only: measure storyboard or NIB text with Apple's Windows CoreText.

Reads caller-supplied fonts in place. It does not install, copy, or bundle them.
CoreText is used as an independent layout probe, not a production OpenIB input.
"""

import argparse
import ctypes
from pathlib import Path
import struct
import xml.etree.ElementTree as ET


class Range(ctypes.Structure):
    _fields_ = [("location", ctypes.c_longlong), ("length", ctypes.c_longlong)]


class Size(ctypes.Structure):
    _fields_ = [("width", ctypes.c_double), ("height", ctypes.c_double)]


def nib_text(path: Path) -> str:
    """Return the longest UTF-8 byte value from a modern NIBArchive."""
    data = path.read_bytes()
    if data[:10] != b"NIBArchive":
        raise ValueError("not a NIBArchive")
    _, _, _, _, _, _, count, offset, _, _ = struct.unpack_from("<10I", data, 10)

    def vint(position: int) -> tuple[int, int]:
        value = 0
        for shift in range(0, 35, 7):
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            if byte & 0x80:
                return value, position
        raise ValueError("invalid NIB integer")

    position = offset
    candidates = []
    fixed_sizes = {0: 1, 1: 2, 2: 4, 3: 8, 6: 4, 7: 8, 10: 4}
    for _ in range(count):
        _, position = vint(position)
        kind = data[position]
        position += 1
        if kind == 8:
            length, position = vint(position)
            raw = data[position:position + length]
            position += length
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if decoded.isprintable() or "\n" in decoded:
                candidates.append(decoded)
        elif kind in fixed_sizes:
            position += fixed_sizes[kind]
        elif kind not in (4, 5, 9):
            raise ValueError(f"unknown NIB value type {kind}")
    if not candidates:
        raise ValueError("no UTF-8 text value found")
    return max(candidates, key=len)


def measure(text: str, font_path: Path, point_size: float, widths: list[float], coretext_dir: Path) -> list[tuple[float, float, float]]:
    pointer = ctypes.c_void_p
    cf = ctypes.CDLL(str(coretext_dir / "CoreFoundation.dll"))
    cg = ctypes.CDLL(str(coretext_dir / "CoreGraphics.dll"))
    ct = ctypes.CDLL(str(coretext_dir / "CoreText.dll"))

    cg.CGDataProviderCreateWithFilename.argtypes = [ctypes.c_char_p]
    cg.CGDataProviderCreateWithFilename.restype = pointer
    cg.CGFontCreateWithDataProvider.argtypes = [pointer]
    cg.CGFontCreateWithDataProvider.restype = pointer
    ct.CTFontCreateWithGraphicsFont.argtypes = [pointer, ctypes.c_double, pointer, pointer]
    ct.CTFontCreateWithGraphicsFont.restype = pointer
    cf.CFStringCreateWithBytes.argtypes = [pointer, ctypes.c_char_p, ctypes.c_longlong, ctypes.c_uint, ctypes.c_bool]
    cf.CFStringCreateWithBytes.restype = pointer
    cf.CFStringGetLength.argtypes = [pointer]
    cf.CFStringGetLength.restype = ctypes.c_longlong
    cf.CFAttributedStringCreateMutable.argtypes = [pointer, ctypes.c_longlong]
    cf.CFAttributedStringCreateMutable.restype = pointer
    cf.CFAttributedStringReplaceString.argtypes = [pointer, Range, pointer]
    cf.CFAttributedStringSetAttribute.argtypes = [pointer, Range, pointer, pointer]
    ct.CTFramesetterCreateWithAttributedString.argtypes = [pointer]
    ct.CTFramesetterCreateWithAttributedString.restype = pointer
    ct.CTFramesetterSuggestFrameSizeWithConstraints.argtypes = [pointer, Range, pointer, Size, ctypes.POINTER(Range)]
    ct.CTFramesetterSuggestFrameSizeWithConstraints.restype = Size

    provider = cg.CGDataProviderCreateWithFilename(str(font_path).encode("utf-8"))
    graphics_font = cg.CGFontCreateWithDataProvider(provider) if provider else None
    font = ct.CTFontCreateWithGraphicsFont(graphics_font, point_size, None, None) if graphics_font else None
    if not font:
        raise ValueError(f"CoreText could not load font: {font_path}")
    raw = text.encode("utf-8")
    string = cf.CFStringCreateWithBytes(None, raw, len(raw), 0x08000100, False)
    length = cf.CFStringGetLength(string)
    attributed = cf.CFAttributedStringCreateMutable(None, 0)
    cf.CFAttributedStringReplaceString(attributed, Range(0, 0), string)
    key = pointer.in_dll(ct, "kCTFontAttributeName").value
    cf.CFAttributedStringSetAttribute(attributed, Range(0, length), key, font)
    framesetter = ct.CTFramesetterCreateWithAttributedString(attributed)
    if not framesetter:
        raise ValueError("CoreText could not create a framesetter")

    result = []
    for width in widths:
        fit = Range()
        actual = ct.CTFramesetterSuggestFrameSizeWithConstraints(
            framesetter, Range(0, 0), None, Size(width, 10_000_000), ctypes.byref(fit)
        )
        if fit.length != length:
            raise ValueError(f"only {fit.length}/{length} UTF-16 units fit")
        result.append((width, actual.width, actual.height))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="storyboard/XIB XML or NIBArchive")
    parser.add_argument("font", type=Path, help="caller-supplied TTF/OTF font")
    parser.add_argument("point_size", type=float)
    parser.add_argument("--element-id", help="textView ID when source is XML")
    parser.add_argument("--width", action="append", type=float, required=True, help="text container width; repeatable")
    parser.add_argument("--vertical-inset", type=float, default=16)
    parser.add_argument("--coretext-dir", type=Path, default=Path(r"C:\Program Files\Common Files\Apple\Apple Application Support"))
    args = parser.parse_args()
    if args.source.suffix.lower() == ".nib":
        text = nib_text(args.source)
    else:
        if not args.element_id:
            parser.error("--element-id is required for XML sources")
        element = ET.parse(args.source).find(f".//*[@id='{args.element_id}']")
        if element is None or element.tag != "textView":
            parser.error("--element-id must identify a textView")
        text = element.get("text") or element.findtext("string[@key='text']") or ""
    print(f"characters={len(text)} hard_lines={text.count(chr(10)) + 1}")
    for requested, actual, height in measure(text, args.font, args.point_size, args.width, args.coretext_dir):
        print(f"container_width={requested:g} measured_width={actual:g} text_height={height:g} with_inset={height + args.vertical_inset:g}")


if __name__ == "__main__":
    main()
