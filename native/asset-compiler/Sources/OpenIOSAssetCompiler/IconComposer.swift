import Foundation

// Icon Composer documents (`<name>.icon`: an `icon.json` and its `Assets`)
// are app icon inputs of actool, as `.appiconset`s are. For a deployment
// target that predates layered icons, actool ships a flattened icon. This
// composes the document's static layer stack into one 1024 pt square SVG:
// the background fill, then every visible group and layer from back to front
// with its opacity, scale and solid fill. The Liquid Glass material
// properties (glass, shadow, translucency, specular, blur material,
// lighting) only exist in the system's layered rendering and are not part of
// that composition. Any other property whose result cannot be reproduced
// exactly fails the compilation instead of being approximated.
enum IconComposer {
    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    static let canvas = 1024.0

    private static let materialKeys: Set<String> = [
        "glass", "shadow", "translucency", "specular", "blur-material", "lighting",
        "glass-specializations", "shadow-specializations", "translucency-specializations",
        "specular-specializations", "blur-material-specializations", "lighting-specializations",
    ]
    private static let documentKeys: Set<String> = [
        "fill", "fill-specializations", "groups", "supported-platforms",
        "color-space-for-untagged-svg-colors",
    ]
    private static let groupKeys: Set<String> = [
        "layers", "name", "hidden", "opacity", "position", "blend-mode",
    ]
    private static let layerKeys: Set<String> = [
        "image-name", "name", "hidden", "opacity", "position", "fill", "fill-specializations",
        "blend-mode", "image-name-specializations",
    ]

    /// The composed SVG of `document` (an `.icon` directory) and the
    /// directory its layer images are resolved against.
    static func flattenedSVG(document: URL) throws -> (svg: Data, resources: URL) {
        let path = document.path
        func fail(_ message: String) -> Failure {
            Failure(description: "unsupported Icon Composer document \(path): \(message)")
        }
        let assets = document.appendingPathComponent("Assets", isDirectory: true)
        let json = try Data(contentsOf: document.appendingPathComponent("icon.json"))
        guard let root = try JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            throw fail("icon.json is not an object")
        }
        try check(root, allowed: documentKeys, at: "document", fail)

        if let platforms = root["supported-platforms"] as? [String: Any] {
            let squares = platforms["squares"]
            let shared = (squares as? String) == "shared"
            let listed = (squares as? [String])?.contains { $0.lowercased() == "ios" } ?? false
            guard shared || listed else { throw fail("the document has no iOS (square) icon") }
        }

        var defs = ""
        var body = ""
        var identifier = 0
        func nextID() -> String { identifier += 1; return "icon-composer-\(identifier)" }

        // Background fill.
        let fill = try defaultValue(root["fill"], specializations: root["fill-specializations"], fail)
        switch try parseFill(fill, fail) {
        case .solid(let color):
            body += "<rect width=\"1024\" height=\"1024\" \(color.svgFill)/>"
        case .gradient(let start, let stop, let from, let to):
            let id = nextID()
            defs += "<linearGradient id=\"\(id)\" gradientUnits=\"userSpaceOnUse\" " +
                "x1=\"\(from.x * canvas)\" y1=\"\(from.y * canvas)\" x2=\"\(to.x * canvas)\" y2=\"\(to.y * canvas)\">" +
                "<stop offset=\"0\" \(start.svgStop)/><stop offset=\"1\" \(stop.svgStop)/></linearGradient>"
            body += "<rect width=\"1024\" height=\"1024\" fill=\"url(#\(id))\"/>"
        case .none:
            throw fail("an automatic or absent background fill has no documented flattened rendering")
        }

        // Groups and layers are listed front to back.
        let groups = root["groups"] as? [[String: Any]] ?? []
        for group in groups.reversed() {
            try check(group, allowed: groupKeys, at: "group", fail)
            if group["hidden"] as? Bool == true { continue }
            try requireNormalBlend(group, fail)
            let groupScale = try scale(of: group["position"], fail)
            var groupBody = ""
            for layer in (group["layers"] as? [[String: Any]] ?? []).reversed() {
                try check(layer, allowed: layerKeys, at: "layer", fail)
                if layer["hidden"] as? Bool == true { continue }
                try requireNormalBlend(layer, fail)
                if layer["image-name-specializations"] != nil {
                    throw fail("appearance-specific layer images are not supported")
                }
                guard let name = layer["image-name"] as? String, !name.isEmpty,
                      !name.contains("/"), !name.contains("\\"), name != ".", name != ".." else {
                    throw fail("a layer has no valid image-name")
                }
                let file = assets.appendingPathComponent(name)
                guard let bytes = try? Data(contentsOf: file) else { throw fail("missing layer image \(name)") }
                let (mime, size) = try imageInfo(bytes, name: name, fail)
                let layerScale = try scale(of: layer["position"], fail)
                let opacity = try unitValue(layer["opacity"], name: "layer opacity", fail)
                let transform = "translate(512 512) scale(\(layerScale)) translate(\(-size.width / 2) \(-size.height / 2))"
                let image = "<image width=\"\(size.width)\" height=\"\(size.height)\" " +
                    "href=\"data:\(mime);base64,\(bytes.base64EncodedString())\"/>"
                var drawn = image
                let layerFill = try defaultValue(layer["fill"], specializations: layer["fill-specializations"], fail)
                switch try parseFill(layerFill, fail) {
                case .solid(let color):
                    // A solid layer fill paints the layer's shape in that color.
                    let id = nextID()
                    defs += "<filter id=\"\(id)\" x=\"0\" y=\"0\" width=\"1\" height=\"1\" color-interpolation-filters=\"sRGB\">" +
                        "<feFlood \(color.svgFlood)/><feComposite in2=\"SourceAlpha\" operator=\"in\"/></filter>"
                    drawn = "<g filter=\"url(#\(id))\">\(image)</g>"
                case .gradient:
                    throw fail("gradient layer fills are not supported")
                case .none:
                    break
                }
                groupBody += "<g transform=\"\(transform)\" opacity=\"\(opacity)\">\(drawn)</g>"
            }
            let groupOpacity = try unitValue(group["opacity"], name: "group opacity", fail)
            body += "<g transform=\"translate(512 512) scale(\(groupScale)) translate(-512 -512)\" " +
                "opacity=\"\(groupOpacity)\">\(groupBody)</g>"
        }

        let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1024\" height=\"1024\" viewBox=\"0 0 1024 1024\">" +
            "<defs>\(defs)</defs>\(body)</svg>"
        return (Data(svg.utf8), assets)
    }

    // MARK: - Properties

    private static func check(_ object: [String: Any], allowed: Set<String>, at place: String,
                              _ fail: (String) -> Failure) throws {
        for key in object.keys where !allowed.contains(key) && !materialKeys.contains(key) {
            throw fail("\(place) property '\(key)' is not supported")
        }
    }

    private static func requireNormalBlend(_ object: [String: Any], _ fail: (String) -> Failure) throws {
        if let mode = object["blend-mode"] as? String, mode != "normal" {
            throw fail("blend mode '\(mode)' is not supported")
        }
    }

    /// The value for the default (light) appearance: an entry of the
    /// specializations without an appearance wins over the plain value.
    private static func defaultValue(_ value: Any?, specializations: Any?, _ fail: (String) -> Failure) throws -> Any? {
        guard let entries = specializations as? [[String: Any]] else { return value }
        for entry in entries where entry["appearance"] == nil {
            return entry["value"]
        }
        return value
    }

    private static func scale(of position: Any?, _ fail: (String) -> Failure) throws -> Double {
        guard let position else { return 1 }
        guard let object = position as? [String: Any] else { throw fail("position is not an object") }
        for key in object.keys where key != "scale" && key != "translation-in-points" {
            throw fail("position property '\(key)' is not supported")
        }
        if let translation = object["translation-in-points"] as? [Double], translation.contains(where: { $0 != 0 }) {
            throw fail("translated layers or groups are not supported")
        }
        guard let scale = (object["scale"] as? NSNumber)?.doubleValue ?? (object["scale"] == nil ? 1 : nil),
              scale > 0, scale.isFinite else { throw fail("invalid position scale") }
        return scale
    }

    private static func unitValue(_ value: Any?, name: String, _ fail: (String) -> Failure) throws -> Double {
        guard let value else { return 1 }
        guard let number = (value as? NSNumber)?.doubleValue, number >= 0, number <= 1 else {
            throw fail("invalid \(name)")
        }
        return number
    }

    // MARK: - Fills and colors

    private enum Fill {
        case solid(Color)
        case gradient(Color, Color, (x: Double, y: Double), (x: Double, y: Double))
        case none
    }

    private static func parseFill(_ value: Any?, _ fail: (String) -> Failure) throws -> Fill {
        guard let value else { return .none }
        if let text = value as? String {
            guard text == "automatic" || text == "none" else { throw fail("fill '\(text)' is not supported") }
            return .none
        }
        guard let object = value as? [String: Any] else { throw fail("fill is not an object") }
        if let solid = object["solid"] as? String {
            return .solid(try Color(solid, fail))
        }
        if let stops = object["linear-gradient"] as? [String] {
            guard stops.count == 2 else { throw fail("a linear gradient needs two colors") }
            var from = (x: 0.5, y: 0.0), to = (x: 0.5, y: 1.0)
            if let orientation = object["orientation"] as? [String: Any] {
                func point(_ key: String) throws -> (x: Double, y: Double) {
                    guard let p = orientation[key] as? [String: Any],
                          let x = (p["x"] as? NSNumber)?.doubleValue, let y = (p["y"] as? NSNumber)?.doubleValue else {
                        throw fail("invalid gradient orientation")
                    }
                    return (x, y)
                }
                from = try point("start"); to = try point("stop")
            }
            return .gradient(try Color(stops[0], fail), try Color(stops[1], fail), from, to)
        }
        if object["automatic-gradient"] != nil {
            throw fail("automatic gradients have no documented flattened rendering")
        }
        throw fail("fill \(object.keys.sorted()) is not supported")
    }

    /// A color in Icon Composer's `<space>:<components>` notation, converted
    /// to 8-bit sRGB.
    struct Color {
        var red: Double, green: Double, blue: Double, alpha: Double

        init(_ text: String, _ fail: (String) -> Failure) throws {
            guard let colon = text.firstIndex(of: ":") else { throw fail("color '\(text)' has no color space") }
            let space = text[..<colon].lowercased()
            let values = text[text.index(after: colon)...].split(separator: ",").map {
                Double($0.trimmingCharacters(in: .whitespaces))
            }
            guard values.allSatisfy({ $0 != nil }) else { throw fail("invalid color '\(text)'") }
            let c = values.map { $0! }
            switch (space, c.count) {
            case ("srgb", 4), ("extended-srgb", 4):
                (red, green, blue, alpha) = (c[0], c[1], c[2], c[3])
            case ("display-p3", 4), ("extended-display-p3", 4):
                (red, green, blue) = Color.p3ToSRGB(c[0], c[1], c[2])
                alpha = c[3]
            case ("gray", 2), ("extended-gray", 2):
                (red, green, blue, alpha) = (c[0], c[0], c[0], c[1])
            default:
                throw fail("color space of '\(text)' is not supported")
            }
            alpha = min(1, max(0, alpha))
        }

        // Display P3 and sRGB share the sRGB transfer function and white
        // point; the primaries differ.
        static func p3ToSRGB(_ r: Double, _ g: Double, _ b: Double) -> (Double, Double, Double) {
            func linear(_ v: Double) -> Double {
                let a = abs(v)
                let l = a <= 0.04045 ? a / 12.92 : pow((a + 0.055) / 1.055, 2.4)
                return v < 0 ? -l : l
            }
            func encode(_ v: Double) -> Double {
                let a = abs(v)
                let e = a <= 0.0031308 ? a * 12.92 : 1.055 * pow(a, 1 / 2.4) - 0.055
                return v < 0 ? -e : e
            }
            let (lr, lg, lb) = (linear(r), linear(g), linear(b))
            return (encode(1.2249401 * lr - 0.2249404 * lg + 0.0000000 * lb),
                    encode(-0.0420569 * lr + 1.0420571 * lg + 0.0000000 * lb),
                    encode(-0.0196376 * lr - 0.0786361 * lg + 1.0982735 * lb))
        }

        private var hex: String {
            func byte(_ v: Double) -> Int { Int((min(1, max(0, v)) * 255).rounded()) }
            return String(format: "#%02x%02x%02x", byte(red), byte(green), byte(blue))
        }
        var svgFill: String { "fill=\"\(hex)\" fill-opacity=\"\(alpha)\"" }
        var svgStop: String { "stop-color=\"\(hex)\" stop-opacity=\"\(alpha)\"" }
        var svgFlood: String { "flood-color=\"\(hex)\" flood-opacity=\"\(alpha)\"" }
    }

    // MARK: - Layer images

    private static func imageInfo(_ bytes: Data, name: String,
                                  _ fail: (String) -> Failure) throws -> (String, (width: Double, height: Double)) {
        let header = [UInt8](bytes.prefix(24))
        if header.count >= 24, header[0..<8].elementsEqual([137, 80, 78, 71, 13, 10, 26, 10]) {
            func big(_ at: Int) -> Double { Double(header[at..<at + 4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }) }
            return ("image/png", (big(16), big(20)))
        }
        guard (name as NSString).pathExtension.lowercased() == "svg",
              let text = String(data: bytes, encoding: .utf8),
              let open = text.range(of: "<svg") else {
            throw fail("layer image \(name) is neither PNG nor SVG")
        }
        let tag = String(text[open.lowerBound...].prefix { $0 != ">" })
        func attribute(_ key: String) -> String? {
            guard let regex = try? NSRegularExpression(pattern: "\\s\(key)\\s*=\\s*[\"']([^\"']*)[\"']"),
                  let match = regex.firstMatch(in: tag, range: NSRange(tag.startIndex..., in: tag)),
                  let range = Range(match.range(at: 1), in: tag) else { return nil }
            return String(tag[range])
        }
        func length(_ value: String?) -> Double? {
            guard var value = value?.trimmingCharacters(in: .whitespaces) else { return nil }
            if value.hasSuffix("px") { value.removeLast(2) }
            return Double(value)
        }
        if let width = length(attribute("width")), let height = length(attribute("height")), width > 0, height > 0 {
            return ("image/svg+xml", (width, height))
        }
        if let box = attribute("viewBox")?.split(whereSeparator: { $0 == " " || $0 == "," }).compactMap({ Double($0) }),
           box.count == 4, box[2] > 0, box[3] > 0 {
            return ("image/svg+xml", (box[2], box[3]))
        }
        throw fail("layer image \(name) has no size")
    }
}
