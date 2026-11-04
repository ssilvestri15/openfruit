"""Diagnostic only: estimate UITextView line wrapping with a supplied font.

This is not part of the OpenIB compiler. Proprietary font data is read from
the path passed by the caller and is neither copied nor embedded.
"""

import argparse
import struct
import xml.etree.ElementTree as ET

from PIL import ImageFont


def sfnt_info(path: str, point_size: int) -> tuple[dict[str, float], str]:
    """Read raw font line metrics; collection fonts need an explicit face."""
    with open(path, "rb") as source:
        data = source.read()
    if data[:4] == b"ttcf":
        return {}, "collection face/version not decoded"
    count = struct.unpack_from(">H", data, 4)[0]
    tables = {}
    for index in range(count):
        tag, _, offset, _ = struct.unpack_from(">4sIII", data, 12 + 16 * index)
        tables[tag] = offset
    if b"head" not in tables or b"hhea" not in tables:
        return {}, "unknown"
    units = struct.unpack_from(">H", data, tables[b"head"] + 18)[0]
    up, down, gap = struct.unpack_from(">hhh", data, tables[b"hhea"] + 4)
    result = {"hhea": (up - down + gap) * point_size / units}
    if b"OS/2" in tables:
        up, down, gap = struct.unpack_from(">hhh", data, tables[b"OS/2"] + 68)
        result["typo"] = (up - down + gap) * point_size / units
    version = "unknown"
    if b"name" in tables:
        offset = tables[b"name"]
        records, string_offset = struct.unpack_from(">HH", data, offset + 2)
        for index in range(records):
            platform, _, _, name_id, length, relative = struct.unpack_from(">HHHHHH", data, offset + 6 + 12 * index)
            if name_id != 5:
                continue
            raw = data[offset + string_offset + relative:offset + string_offset + relative + length]
            try:
                version = raw.decode("utf-16-be" if platform in (0, 3) else "latin-1")
                break
            except UnicodeDecodeError:
                pass
    return result, version


def wrapped_lines(text: str, font: ImageFont.FreeTypeFont, width: float) -> list[str]:
    result = []
    for paragraph in text.split("\n"):
        if not paragraph:
            result.append("")
            continue
        line = ""
        for word in paragraph.split(" "):
            proposed = word if not line else line + " " + word
            if line and font.getlength(proposed) > width:
                result.append(line)
                line = word
            else:
                line = proposed
            while font.getlength(line) > width:
                cut = max(i for i in range(1, len(line) + 1) if font.getlength(line[:i]) <= width)
                result.append(line[:cut])
                line = line[cut:]
        result.append(line)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("storyboard")
    parser.add_argument("element_id")
    parser.add_argument("font_file")
    parser.add_argument("point_size", type=int)
    parser.add_argument("--inset", type=float, default=5, help="horizontal fragment padding per side")
    parser.add_argument("--show-lines", action="store_true", help="print each estimated line for diagnosing word breaks")
    args = parser.parse_args()
    node = ET.parse(args.storyboard).find(f".//*[@id='{args.element_id}']")
    if node is None or node.tag != "textView":
        parser.error("element_id must identify a textView")
    frame = node.find("rect[@key='frame']")
    if frame is None:
        parser.error("textView needs a frame")
    text = node.get("text") or node.findtext("string[@key='text']") or ""
    width = float(frame.get("width")) - 2 * args.inset
    font = ImageFont.truetype(args.font_file, args.point_size)
    lines = wrapped_lines(text, font, width)
    ascent, descent = font.getmetrics()
    print(f"font={font.getname()} point_size={args.point_size} width={width:g}")
    print(f"characters={len(text)} hard_lines={text.count(chr(10)) + 1} wrapped_lines={len(lines)}")
    print(f"ascent={ascent} descent={descent} PIL_line_height={ascent + descent}")
    raw_metrics, version = sfnt_info(args.font_file, args.point_size)
    print(f"font_version={version} raw_line_metrics={raw_metrics}")
    if "typo" in raw_metrics:
        print(f"height_at_rounded_typo_line_height_plus_16={len(lines) * round(raw_metrics['typo']) + 16}")
    print(f"height_at_PIL_line_height_plus_16={len(lines) * (ascent + descent) + 16}")
    print(f"longest_line_advance={max((font.getlength(line) for line in lines), default=0):g}")
    if args.show_lines:
        for index, line in enumerate(lines, 1):
            print(f"{index:3}: {font.getlength(line):6.1f} {line!r}")


if __name__ == "__main__":
    main()
