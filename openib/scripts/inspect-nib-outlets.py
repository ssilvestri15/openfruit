"""Diagnostic: show outlet endpoint identities from `openib dump` output."""

import argparse
import re
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("openib")
    parser.add_argument("nib")
    parser.add_argument("--controller", help="controller NIB that provides the view's external objects")
    parser.add_argument("--semantic", action="store_true", help="sort connections and replace resolved proxy names with their targets")
    args = parser.parse_args()

    def read_objects(path: str) -> dict:
        output = subprocess.check_output([args.openib, "dump", path], text=True, encoding="utf-8")
        objects = {}
        index = None
        for line in output.splitlines():
            match = re.match(r"^\[(\d+)\] (\S+)$", line)
            if match:
                index = int(match.group(1))
                objects[index] = {"class": match.group(2), "_pairs": []}
            elif index is not None:
                match = re.match(r"^  (\S+) = \([^)]*\) (.*)$", line)
                if match:
                    objects[index][match.group(1)] = match.group(2)
                    objects[index]["_pairs"].append((match.group(1), match.group(2)))
        return objects

    objects = read_objects(args.nib)

    def target(ref: str) -> dict:
        return objects.get(int(ref.removeprefix("@")), {}) if ref.startswith("@") else {}

    def name(ref: str) -> str:
        obj = target(ref)
        if obj.get("class") in ("NSString", "NSLocalizableString", "NSMutableString"):
            return obj.get("NS.bytes", "")[:100]
        if obj.get("class") == "UIProxyObject":
            return "proxy:" + name(obj.get("UIProxiedObjectIdentifier", ""))
        if obj.get("class") in ("UITableViewCell", "UIClassSwapper"):
            reuse = name(obj.get("UIReuseIdentifier", ""))
            center = obj.get("UICenter", "")
            return obj.get("class", "?") + ":" + reuse + ":" + center
        if obj.get("UIText", "").startswith("@"):
            return obj.get("class", "?") + ":" + name(obj["UIText"])
        return obj.get("class", "?")

    external = {}
    if args.controller:
        controller_objects = read_objects(args.controller)
        for obj in controller_objects.values():
            if "UIExternalObjectsTableForViewLoading" not in obj:
                continue
            table_ref = obj["UIExternalObjectsTableForViewLoading"]
            if not table_ref.startswith("@"):
                continue
            table = controller_objects[int(table_ref[1:])]
            refs = [value for key, value in table["_pairs"] if key == "UINibEncoderEmptyKey"]
            for key_ref, value_ref in zip(refs[::2], refs[1::2]):
                key = controller_objects[int(key_ref[1:])].get("NS.bytes", "").strip('"')
                value = controller_objects[int(value_ref[1:])]
                destination = value.get("UIDestinationViewControllerIdentifier", "")
                if destination.startswith("@"):
                    external[key] = controller_objects[int(destination[1:])].get("NS.bytes", "").strip('"')

    connections = []
    for obj in objects.values():
        if obj.get("class") == "UIRuntimeOutletConnection":
            destination = name(obj.get("UIDestination", ""))
            if destination.startswith('proxy:"'):
                identifier = destination.removeprefix('proxy:"').removesuffix('"')
                if identifier in external:
                    destination = external[identifier] if args.semantic else destination + " -> " + external[identifier]
            connections.append(f"{name(obj.get('UILabel', ''))} | {name(obj.get('UISource', ''))} -> {destination}")
    for connection in sorted(connections) if args.semantic else connections:
        print(connection)


if __name__ == "__main__":
    main()
