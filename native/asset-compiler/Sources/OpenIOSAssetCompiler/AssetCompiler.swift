import AssetKit
import Foundation

private enum CommandError: Error, CustomStringConvertible {
    case usage(String)
    case noCatalogs
    case duplicateAsset(String, String, String)
    case unsupportedAsset(String)

    var description: String {
        switch self {
        case .usage(let message): return message
        case .noCatalogs: return "no .xcassets catalogs were supplied"
        case .duplicateAsset(let name, let first, let second):
            return "duplicate asset '\(name)' in \(first) and \(second)"
        case .unsupportedAsset(let path): return "unsupported asset type: \(path)"
        }
    }
}

private struct Options {
    var outputDirectory: URL
    var deploymentTarget: String
    var primaryAppIcon: String?
    // ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS and
    // ASSETCATALOG_COMPILER_ALTERNATE_APPICON_NAMES (actool's
    // --include-all-app-icons and --alternate-app-icon).
    var includeAllAppIcons: Bool
    var alternateAppIcons: [String]
    var svgRasterizer: URL?
    var catalogs: [URL]

    static func parse(_ arguments: [String]) throws -> Options {
        var output: URL?
        var deploymentTarget = "16.0"
        var primaryAppIcon: String?
        var includeAllAppIcons = false
        var alternateAppIcons: [String] = []
        var svgRasterizer: URL?
        var catalogs: [URL] = []
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--output-directory":
                index += 1
                guard index < arguments.count else {
                    throw CommandError.usage("--output-directory requires a path")
                }
                output = URL(fileURLWithPath: arguments[index], isDirectory: true)
            case "--deployment-target":
                index += 1
                guard index < arguments.count else {
                    throw CommandError.usage("--deployment-target requires a version")
                }
                deploymentTarget = arguments[index]
            case "--app-icon":
                index += 1
                guard index < arguments.count else {
                    throw CommandError.usage("--app-icon requires an asset name")
                }
                primaryAppIcon = arguments[index]
            case "--include-all-app-icons":
                includeAllAppIcons = true
            case "--alternate-app-icon":
                index += 1
                guard index < arguments.count else {
                    throw CommandError.usage("--alternate-app-icon requires an asset name")
                }
                if !alternateAppIcons.contains(arguments[index]) { alternateAppIcons.append(arguments[index]) }
            case "--help", "-h":
                throw CommandError.usage(Self.usage)
            case "--svg-rasterizer":
                index += 1
                guard index < arguments.count else {
                    throw CommandError.usage("--svg-rasterizer requires an absolute executable path")
                }
                let path = arguments[index]
                let chars = Array(path)
                let driveAbsolute = chars.count >= 3 && chars[1] == ":" &&
                    (chars[2] == "/" || chars[2] == "\\") && chars[0].isASCII && chars[0].isLetter
                guard path.hasPrefix("/") || path.hasPrefix("\\\\") || driveAbsolute else {
                    throw CommandError.usage("--svg-rasterizer requires an absolute executable path")
                }
                svgRasterizer = URL(fileURLWithPath: path)
            default:
                if argument.hasPrefix("-") {
                    throw CommandError.usage("unknown option: \(argument)\n\(Self.usage)")
                }
                catalogs.append(URL(fileURLWithPath: argument, isDirectory: true))
            }
            index += 1
        }

        guard let output else {
            throw CommandError.usage("--output-directory is required\n\(Self.usage)")
        }
        guard !catalogs.isEmpty else { throw CommandError.noCatalogs }
        return Options(
            outputDirectory: output,
            deploymentTarget: deploymentTarget,
            primaryAppIcon: primaryAppIcon,
            includeAllAppIcons: includeAllAppIcons,
            alternateAppIcons: alternateAppIcons,
            svgRasterizer: svgRasterizer,
            catalogs: catalogs
        )
    }

    static let usage = """
    usage: OPENFRUIT-asset-compiler --output-directory <bundle> \
           [--deployment-target <version>] [--app-icon <name>] \
           [--include-all-app-icons] [--alternate-app-icon <name>]... \
           [--svg-rasterizer <verified-absolute-executable>] <catalog.xcassets>...
    """
}

// A repeated self-contained SVG is independent of its directory. When bytes
// contain external-resource constructs, distinct bases cannot be represented
// by AssetKit's data-only rasterizer interface and must fail explicitly.
private func svgIsSelfContained(_ data: Data) -> Bool {
    guard let text = String(data: data, encoding: .utf8), !text.contains("&") else { return false }
    let whole = NSRange(text.startIndex..<text.endIndex, in: text)
    let dependent = try! NSRegularExpression(pattern: "(?i)xml:base|<!DOCTYPE|<!ENTITY|@import")
    guard dependent.firstMatch(in: text, range: whole) == nil else { return false }
    for pattern in ["(?i)\\bhref\\s*=\\s*[\"']([^\"']*)[\"']",
                    "(?i)url\\s*\\(\\s*[\"']?([^\\s\\)\"']+)"] {
        let regex = try! NSRegularExpression(pattern: pattern)
        for match in regex.matches(in: text, range: whole) {
            guard let range = Range(match.range(at: 1), in: text) else { return false }
            let reference = text[range].trimmingCharacters(in: .whitespacesAndNewlines)
            if !reference.hasPrefix("#") && !reference.lowercased().hasPrefix("data:") { return false }
        }
    }
    return true
}

// Replaces referenced images held as Photoshop documents in a staged set
// with their composite as PNG; other image bytes are left to AssetKit.
private func transcodeDocumentImages(in set: URL) throws {
    let metadata = try Data(contentsOf: set.appendingPathComponent("Contents.json"))
    let contents = try JSONSerialization.jsonObject(with: metadata) as? [String: Any]
    for image in contents?["images"] as? [[String: Any]] ?? [] {
        guard let filename = image["filename"] as? String, !filename.isEmpty else { continue }
        let file = set.appendingPathComponent(filename)
        guard let data = try? Data(contentsOf: file), PSDComposite.isDocument(data) else { continue }
        try PSDComposite.pngData(fromDocument: data, path: file.path).write(to: file, options: .atomic)
    }
}

private func collectAssetSets(
    from catalog: URL,
    primaryAppIcon: String?,
    alternateAppIcon: (String) -> Bool,
    alternates: inout [String: URL],
    into aggregate: URL,
    outputBundle: URL,
    seen: inout [String: String],
    svgResources: inout [Data: URL]
) throws {
    let manager = FileManager.default
    func visit(_ directory: URL) throws {
        let children = try manager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        for entry in children {
            let values = try entry.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else { continue }

        let ext = entry.pathExtension.lowercased()
        let assetName = entry.deletingPathExtension().lastPathComponent
        let supported: Bool
        switch ext {
        case "imageset", "colorset":
            supported = true
        case "appiconset":
            supported = primaryAppIcon == nil || assetName == primaryAppIcon
            // An alternate icon is compiled on its own; its set is staged apart.
            if !supported && alternateAppIcon(assetName) {
                let identity = "appiconset:\(assetName)"
                if let first = seen[identity] {
                    throw CommandError.duplicateAsset(assetName, first, entry.path)
                }
                seen[identity] = entry.path
                alternates[assetName] = entry
                continue
            }
        case "symbolset", "dataset":
            supported = true
        default:
            supported = false
        }

        // Layered-image containers of other platforms (visionOS solid image
        // stacks, tvOS image stacks and brand assets) have no iOS rendition;
        // an iOS catalog compilation skips them, as actool does.
        if ["solidimagestack", "imagestack", "brandassets"].contains(ext) { continue }
        if !["imageset", "colorset", "appiconset", "symbolset", "dataset"].contains(ext) {
            if ext.isEmpty {
                try visit(entry)
                continue
            }
            throw CommandError.unsupportedAsset(entry.path)
        }

        guard supported else { continue }

        // AssetKit validates the files actually referenced by Contents.json.
        // Unrelated directory files must not suppress a required rendition.
        let identity = "\(ext):\(assetName)"
        if let first = seen[identity] {
            throw CommandError.duplicateAsset(assetName, first, entry.path)
        }
        if ext == "dataset" {
            let metadataURL = entry.appendingPathComponent("Contents.json")
            if let metadata = try? Data(contentsOf: metadataURL),
               let contents = try? JSONSerialization.jsonObject(with: metadata) as? [String: Any],
               let dataItems = contents["data"] as? [[String: Any]] {
                for item in dataItems {
                    guard let filename = item["filename"] as? String, !filename.isEmpty else { continue }
                    let source = entry.appendingPathComponent(filename).standardizedFileURL
                    guard manager.fileExists(atPath: source.path) else { continue }
                    let destination = outputBundle.appendingPathComponent(filename)
                    try? manager.removeItem(at: destination)
                    try manager.copyItem(at: source, to: destination)
                }
            }
            let datasetDest = outputBundle.appendingPathComponent(entry.lastPathComponent)
            try? manager.removeItem(at: datasetDest)
            try manager.copyItem(at: entry, to: datasetDest)
            seen[identity] = entry.path
            continue
        }
        if ext == "symbolset" {
            let metadataURL = entry.appendingPathComponent("Contents.json")
            let metadata = try Data(contentsOf: metadataURL)
            let contents = try JSONSerialization.jsonObject(with: metadata) as? [String: Any]
            let symbols = contents?["symbols"] as? [[String: Any]] ?? []
            let targetImageset = aggregate.appendingPathComponent("\(assetName).imageset")
            try manager.createDirectory(at: targetImageset, withIntermediateDirectories: true)
            var synthesizedImages: [[String: Any]] = []
            for symbol in symbols {
                guard let filename = symbol["filename"] as? String, !filename.isEmpty else { continue }
                var img: [String: Any] = ["filename": filename]
                if let idiom = symbol["idiom"] as? String { img["idiom"] = idiom }
                synthesizedImages.append(img)
                let source = entry.appendingPathComponent(filename).standardizedFileURL
                guard manager.fileExists(atPath: source.path) else { continue }
                let targetFile = targetImageset.appendingPathComponent(filename)
                try? manager.removeItem(at: targetFile)
                try manager.copyItem(at: source, to: targetFile)
                if (filename as NSString).pathExtension.lowercased() == "svg" {
                    let attributes = try manager.attributesOfItem(atPath: source.path)
                    guard let size = attributes[.size] as? NSNumber, size.uint64Value <= 64 * 1024 * 1024 else {
                        throw CommandError.usage("Referenced SVG exceeds the 64 MiB input limit: \(source.path)")
                    }
                    let bytes = try Data(contentsOf: source)
                    let parent = targetImageset
                    if let previous = svgResources[bytes], previous != parent {
                        guard svgIsSelfContained(bytes) else {
                            throw CommandError.usage("Identical SVG bytes with external resources in different directories are unsupported: \(previous.path), \(parent.path)")
                        }
                    } else {
                        svgResources[bytes] = parent
                    }
                }
            }
            let synthesizedContents: [String: Any] = [
                "info": ["author": "xcode", "version": 1],
                "images": synthesizedImages,
                "properties": ["preserves-vector-representation": true]
            ]
            let synthData = try JSONSerialization.data(withJSONObject: synthesizedContents, options: [.prettyPrinted])
            try synthData.write(to: targetImageset.appendingPathComponent("Contents.json"), options: .atomic)
            seen[identity] = entry.path
            continue
        }
        if ext == "imageset" {
            let metadataURL = entry.appendingPathComponent("Contents.json")
            let metadata = try Data(contentsOf: metadataURL)
            let contents = try JSONSerialization.jsonObject(with: metadata) as? [String: Any]
            let images = contents?["images"] as? [[String: Any]] ?? []
            for image in images {
                guard let filename = image["filename"] as? String,
                      (filename as NSString).pathExtension.lowercased() == "svg" else { continue }
                let source = entry.appendingPathComponent(filename).standardizedFileURL
                // AssetKit retains responsibility for its missing-file diagnostic.
                guard manager.fileExists(atPath: source.path) else { continue }
                let attributes = try manager.attributesOfItem(atPath: source.path)
                guard let size = attributes[.size] as? NSNumber, size.uint64Value <= 64 * 1024 * 1024 else {
                    throw CommandError.usage("Referenced SVG exceeds the 64 MiB input limit: \(source.path)")
                }
                let bytes = try Data(contentsOf: source)
                let parent = source.deletingLastPathComponent()
                if let previous = svgResources[bytes], previous != parent {
                    guard svgIsSelfContained(bytes) else {
                        throw CommandError.usage("Identical SVG bytes with external resources in different directories are unsupported: \(previous.path), \(parent.path)")
                    }
                } else {
                    svgResources[bytes] = parent
                }
            }
        }
        seen[identity] = entry.path
        let staged = aggregate.appendingPathComponent(entry.lastPathComponent)
        try manager.copyItem(at: entry, to: staged)
        if ext == "imageset" || ext == "appiconset" { try transcodeDocumentImages(in: staged) }
        }
    }
    try visit(catalog)
}

private struct OPENFRUITSVGRasterizer: SVGRasterizer {
    let executable: URL?
    let resources: [Data: URL]

    private func failure(_ message: String) -> NSError {
        NSError(domain: "OPENFRUITAssetCompiler", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }

    func rasterize(svgData: Data, pixelWidth: UInt32, pixelHeight: UInt32) throws -> Data {
        guard let executable else {
            throw failure("SVG requires the native verified rasterizer supplied by OPENFRUIT (--svg-rasterizer)")
        }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: executable.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            throw failure("Native SVG rasterizer is missing: \(executable.path)")
        }
        guard pixelWidth > 0, pixelHeight > 0,
              UInt64(pixelWidth) * UInt64(pixelHeight) <= 64 * 1024 * 1024,
              svgData.count <= 64 * 1024 * 1024 else {
            throw failure("SVG rasterization exceeds the supported 64 MiB input/64 million pixel limits")
        }
        guard let resourceDirectory = resources[svgData] else {
            throw failure("SVG resource directory could not be derived from the selected catalog's referenced source")
        }
        let process = Process()
        process.executableURL = executable
        // Original resvg v0.45.1 CLI: '-' reads SVG stdin, '-c' writes PNG stdout.
        process.arguments = ["--width", "\(pixelWidth)", "--height", "\(pixelHeight)",
                             "--resources-dir", resourceDirectory.path, "-", "-c"]

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let ended = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in ended.signal() }
        do { try process.run() }
        catch { throw failure("Could not launch native SVG rasterizer: \(error)") }
        let deadline = DispatchTime.now() + .seconds(30)
        let io = DispatchGroup()
        let stdinHandle = stdinPipe.fileHandleForWriting
        let input = CapturedStream(limit: 0)
        let output = CapturedStream(limit: 256 * 1024 * 1024 + 1024 * 1024)
        let diagnostics = CapturedStream(limit: 1024 * 1024)
        io.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            defer { io.leave() }
            do {
                try stdinHandle.write(contentsOf: svgData)
                try stdinHandle.close()
            } catch {
                input.fail("Failed to stream SVG input: \(error)")
                try? stdinHandle.close()
            }
        }
        for (handle, capture) in [(stdoutPipe.fileHandleForReading, output),
                                  (stderrPipe.fileHandleForReading, diagnostics)] {
            io.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { io.leave(); try? handle.close() }
                do {
                    while let chunk = try handle.read(upToCount: 64 * 1024), !chunk.isEmpty {
                        capture.append(chunk)
                    }
                } catch { capture.fail("Failed to read rasterizer output: \(error)") }
            }
        }
        guard ended.wait(timeout: deadline) == .success, io.wait(timeout: deadline) == .success else {
            if process.isRunning { process.terminate() }
            throw failure("Native SVG rasterizer exceeded its 30 second deadline")
        }
        let (stdout, outputError) = output.snapshot()
        let (stderr, diagnosticError) = diagnostics.snapshot()
        let (_, inputError) = input.snapshot()
        guard process.terminationStatus == 0 else {
            throw failure("Native SVG rasterizer exited \(process.terminationStatus): \(String(decoding: stderr, as: UTF8.self))")
        }
        if let error = inputError ?? outputError ?? diagnosticError { throw failure(error) }
        let rendererDiagnostics = String(decoding: stderr, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let diagnosticLines = rendererDiagnostics
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { line in
                if line.isEmpty { return false }
                // Apple SF Symbols templates use proprietary CSS pseudo-classes (:tintColor, :primary, :secondary, :tertiary, :white, etc.)
                // for dynamic runtime symbol tinting. These are standardly skipped by SVG rasterizers when generating static renditions.
                if line.contains("simplecss::selector") && line.contains("Selector skipped") { return false }
                return true
            }
        guard diagnosticLines.isEmpty else {
            throw failure("Native SVG rasterizer reported an incomplete/unsupported rendering: \(diagnosticLines.joined(separator: "\n"))")
        }
        let header = Array(stdout.prefix(33))
        guard header.count == 33,
              Array(header[0..<8]) == [137, 80, 78, 71, 13, 10, 26, 10],
              Array(header[8..<16]) == [0, 0, 0, 13, 73, 72, 68, 82] else {
            throw failure("Native SVG rasterizer produced an invalid PNG header")
        }
        func bigEndian(_ start: Int) -> UInt32 {
            header[start..<start + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        }
        let actualWidth = bigEndian(16)
        let actualHeight = bigEndian(20)
        guard actualWidth > 0 && actualHeight > 0 else {
            throw failure("Native SVG rasterizer produced a zero-dimension image")
        }
        return stdout
    }

    // Drain all three pipes concurrently; retain bounded data and errors only.
    private final class CapturedStream: @unchecked Sendable {
        private let lock = NSLock()
        private let limit: Int
        private var data = Data()
        private var error: String?
        init(limit: Int) { self.limit = limit }
        func append(_ chunk: Data) {
            lock.lock(); defer { lock.unlock() }
            let remaining = max(0, limit - data.count)
            data.append(chunk.prefix(remaining))
            if chunk.count > remaining && error == nil {
                error = "Native SVG rasterizer output exceeded its bounded capture limit"
            }
        }
        func fail(_ message: String) {
            lock.lock(); defer { lock.unlock() }
            if error == nil { error = message }
        }
        func snapshot() -> (Data, String?) {
            lock.lock(); defer { lock.unlock() }; return (data, error)
        }
    }
}

@main
private enum Main {
    static func main() async {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments == ["--help"] || arguments == ["-h"] {
                print(Options.usage)
                return
            }
            if arguments == ["--capabilities"] {
                #if os(Windows)
                let nativeWindows = true
                #else
                let nativeWindows = false
                #endif
                let capabilities: [String: Any] = [
                    "schema": "openfruit.asset-compiler.v1",
                    "svg_backend": "resvg",
                    "svg_warning_policy": "error",
                    "native_windows": nativeWindows,
                    "other_platform_layered_images": "skipped",
                    "photoshop_composites": "decoded",
                    "alternate_app_icons": "partial_info_plist",
                    "icon_composer_documents": "flattened_static_layers",
                ]
                let data = try JSONSerialization.data(withJSONObject: capabilities, options: [.sortedKeys])
                FileHandle.standardOutput.write(data)
                FileHandle.standardOutput.write(Data("\n".utf8))
                return
            }
            let options = try Options.parse(arguments)
            let manager = FileManager.default
            let scratch = manager.temporaryDirectory
                .appendingPathComponent("OPENFRUIT-xcassets-\(UUID().uuidString)", isDirectory: true)
            defer { try? manager.removeItem(at: scratch) }
            try manager.createDirectory(at: scratch, withIntermediateDirectories: true)

            var seen: [String: String] = [:]
            var svgResources: [Data: URL] = [:]
            var alternates: [String: URL] = [:]
            let alternateAppIcon = { (name: String) in
                options.includeAllAppIcons || options.alternateAppIcons.contains(name)
            }
            let primaryScratch = scratch.appendingPathComponent("Primary.xcassets", isDirectory: true)
            try manager.createDirectory(at: primaryScratch, withIntermediateDirectories: true)
            // Icon Composer documents become single-size app icon sets of a
            // staged catalog, then follow the primary/alternate selection.
            var catalogs: [URL] = []
            let iconDocuments = options.catalogs.filter { $0.pathExtension.lowercased() == "icon" }
            if !iconDocuments.isEmpty {
                let iconCatalog = scratch.appendingPathComponent("IconComposer.xcassets", isDirectory: true)
                for document in iconDocuments {
                    let name = document.deletingPathExtension().lastPathComponent
                    let (svg, resources) = try IconComposer.flattenedSVG(document: document)
                    let png = try OPENFRUITSVGRasterizer(executable: options.svgRasterizer, resources: [svg: resources])
                        .rasterize(svgData: svg, pixelWidth: 1024, pixelHeight: 1024)
                    let set = iconCatalog.appendingPathComponent("\(name).appiconset", isDirectory: true)
                    guard !manager.fileExists(atPath: set.path) else {
                        throw CommandError.duplicateAsset(name, document.path, document.path)
                    }
                    try manager.createDirectory(at: set, withIntermediateDirectories: true)
                    try png.write(to: set.appendingPathComponent("\(name).png"), options: .atomic)
                    let contents: [String: Any] = [
                        "images": [["filename": "\(name).png", "idiom": "universal", "platform": "ios", "size": "1024x1024"]],
                        "info": ["author": "xcode", "version": 1],
                    ]
                    try JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
                        .write(to: set.appendingPathComponent("Contents.json"), options: .atomic)
                }
                catalogs.append(iconCatalog)
            }
            catalogs += options.catalogs.filter { $0.pathExtension.lowercased() != "icon" }
            for catalog in catalogs {
                try collectAssetSets(
                    from: catalog,
                    primaryAppIcon: options.primaryAppIcon,
                    alternateAppIcon: alternateAppIcon,
                    alternates: &alternates,
                    into: primaryScratch,
                    outputBundle: options.outputDirectory,
                    seen: &seen,
                    svgResources: &svgResources
                )
            }

            let compiler = XCAssetCompiler(
                deploymentTarget: options.deploymentTarget,
                svgRasterizer: OPENFRUITSVGRasterizer(executable: options.svgRasterizer, resources: svgResources)
            )
            let result = try await compiler.compile(catalog: primaryScratch)
            try manager.createDirectory(
                at: options.outputDirectory,
                withIntermediateDirectories: true
            )
            try result.carData.write(
                to: options.outputDirectory.appendingPathComponent("Assets.car"),
                options: .atomic
            )

            var additions: [String: Any] = [:]
            if let iconBundle = result.appIconBundle {
                for file in iconBundle.looseFiles {
                    try file.data.write(
                        to: options.outputDirectory.appendingPathComponent(file.name),
                        options: .atomic
                    )
                }
                additions = iconBundle.infoPlistAdditions.reduce(into: [String: Any]()) {
                    $0[$1.key] = $1.value
                }
            }

            // Requested alternates must exist, as the primary app icon must.
            for name in options.alternateAppIcons where alternates[name] == nil && name != options.primaryAppIcon {
                throw CommandError.usage("None of the input catalogs contained a matching app icon set named \"\(name)\".")
            }
            // Each alternate app icon is compiled alone: its loose icon files
            // ship in the bundle and its primary-icon declaration becomes the
            // CFBundleAlternateIcons entry setAlternateIconName(_:) resolves.
            for (index, name) in alternates.keys.sorted().enumerated() {
                let catalog = scratch.appendingPathComponent("Alternate-\(index).xcassets", isDirectory: true)
                try manager.createDirectory(at: catalog, withIntermediateDirectories: true)
                let staged = catalog.appendingPathComponent("\(name).appiconset")
                try manager.copyItem(at: alternates[name]!, to: staged)
                try transcodeDocumentImages(in: staged)
                guard let iconBundle = try await compiler.compile(catalog: catalog).appIconBundle else {
                    throw CommandError.usage("app icon set \(name) produced no icon")
                }
                for file in iconBundle.looseFiles {
                    try file.data.write(
                        to: options.outputDirectory.appendingPathComponent(file.name),
                        options: .atomic
                    )
                }
                for key in ["CFBundleIcons", "CFBundleIcons~ipad"] {
                    guard let declared = iconBundle.infoPlistAdditions[key] as? [String: any Sendable],
                          let icon = declared["CFBundlePrimaryIcon"] else { continue }
                    var icons = additions[key] as? [String: Any] ?? [:]
                    var alternateIcons = icons["CFBundleAlternateIcons"] as? [String: Any] ?? [:]
                    alternateIcons[name] = icon
                    icons["CFBundleAlternateIcons"] = alternateIcons
                    additions[key] = icons
                }
            }

            if !additions.isEmpty {
                let plist = try PropertyListSerialization.data(
                    fromPropertyList: additions,
                    format: .xml,
                    options: 0
                )
                try plist.write(
                    to: options.outputDirectory.appendingPathComponent("assetcatalog_generated_info.plist"),
                    options: .atomic
                )
            }

            print("OPENFRUIT Asset Compiler: wrote \(seen.count) asset set(s) to \(options.outputDirectory.path)/Assets.car")
        } catch {
            FileHandle.standardError.write(Data("OPENFRUIT Asset Compiler: \(error)\n".utf8))
            Foundation.exit(EXIT_FAILURE)
        }
    }
}

// Asset catalog image files are decoded by content, as ImageIO does for
// actool: a referenced file holding a Photoshop document is compiled from its
// flattened composite. This decodes that composite (version 1, 8-bit RGB or
// grayscale, raw or PackBits) and re-encodes it as an RGBA PNG.
enum PSDComposite {
    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    static func isDocument(_ data: Data) -> Bool {
        data.count >= 4 && data.prefix(4).elementsEqual([0x38, 0x42, 0x50, 0x53]) // "8BPS"
    }

    static func pngData(fromDocument data: Data, path: String) throws -> Data {
        let bytes = [UInt8](data)
        var offset = 0
        func fail(_ message: String) -> Failure { Failure(description: "unsupported Photoshop image \(path): \(message)") }
        func u16() throws -> Int {
            guard offset + 2 <= bytes.count else { throw fail("truncated") }
            defer { offset += 2 }
            return Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        }
        func u32() throws -> Int {
            guard offset + 4 <= bytes.count else { throw fail("truncated") }
            defer { offset += 4 }
            return Int(bytes[offset]) << 24 | Int(bytes[offset + 1]) << 16 | Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
        }
        offset = 4
        guard try u16() == 1 else { throw fail("only version 1 (PSD) documents are supported") }
        offset += 6
        let channels = try u16(), height = try u32(), width = try u32(), depth = try u16(), mode = try u16()
        guard depth == 8 else { throw fail("bit depth \(depth)") }
        let colorChannels: Int
        switch mode {
        case 3: colorChannels = 3 // RGB
        case 1: colorChannels = 1 // grayscale
        default: throw fail("color mode \(mode)")
        }
        guard channels >= colorChannels, width > 0, height > 0, width <= 16384, height <= 16384 else {
            throw fail("\(channels) channels, \(width)x\(height)")
        }
        // Color mode data, image resources, then layer and mask information.
        for _ in 0..<3 {
            let length = try u32()
            guard offset + length <= bytes.count else { throw fail("truncated section") }
            offset += length
        }
        let compression = try u16()
        let planeSize = width * height
        // The composite stores every channel plane; only color and the first
        // extra (merged transparency) plane are used.
        let used = min(channels, colorChannels + 1)
        var planes = [[UInt8]](repeating: [], count: used)
        switch compression {
        case 0:
            guard offset + planeSize * channels <= bytes.count else { throw fail("truncated raw data") }
            for plane in 0..<used {
                planes[plane] = Array(bytes[(offset + plane * planeSize)..<(offset + (plane + 1) * planeSize)])
            }
        case 1:
            var counts: [Int] = []
            counts.reserveCapacity(channels * height)
            for _ in 0..<(channels * height) { counts.append(try u16()) }
            for plane in 0..<channels {
                var output: [UInt8] = []
                output.reserveCapacity(planeSize)
                for row in 0..<height {
                    let end = offset + counts[plane * height + row]
                    guard end <= bytes.count else { throw fail("truncated PackBits data") }
                    var line: [UInt8] = []
                    line.reserveCapacity(width)
                    while offset < end {
                        let header = Int(Int8(bitPattern: bytes[offset])); offset += 1
                        if header >= 0 {
                            let count = header + 1
                            guard offset + count <= end else { throw fail("invalid PackBits literal") }
                            line.append(contentsOf: bytes[offset..<(offset + count)]); offset += count
                        } else if header != -128 {
                            guard offset < end else { throw fail("invalid PackBits run") }
                            line.append(contentsOf: repeatElement(bytes[offset], count: 1 - header)); offset += 1
                        }
                    }
                    guard line.count == width else { throw fail("PackBits row length \(line.count) != \(width)") }
                    output.append(contentsOf: line)
                }
                if plane < used { planes[plane] = output }
            }
        default:
            throw fail("compression \(compression)")
        }
        var rgba = [UInt8](repeating: 0, count: planeSize * 4)
        let hasAlpha = used > colorChannels
        for index in 0..<planeSize {
            let alpha = hasAlpha ? Int(planes[colorChannels][index]) : 255
            for component in 0..<3 {
                var value = Int(planes[colorChannels == 3 ? component : 0][index])
                // The merged composite of a transparent document is matted
                // against white; recover the unmatted color.
                if hasAlpha && alpha > 0 && alpha < 255 {
                    value = min(255, max(0, ((value - (255 - alpha)) * 255 + alpha / 2) / alpha))
                }
                rgba[index * 4 + component] = alpha == 0 ? 0 : UInt8(value)
            }
            rgba[index * 4 + 3] = UInt8(alpha)
        }
        return PNGWriter.rgba(width: width, height: height, pixels: rgba)
    }
}

enum PNGWriter {
    static func rgba(width: Int, height: Int, pixels: [UInt8]) -> Data {
        var raw: [UInt8] = []
        raw.reserveCapacity(height * (width * 4 + 1))
        for row in 0..<height {
            raw.append(0) // filter: none
            raw.append(contentsOf: pixels[(row * width * 4)..<((row + 1) * width * 4)])
        }
        // zlib stream of stored deflate blocks.
        var zlib: [UInt8] = [0x78, 0x01]
        var position = 0
        repeat {
            let count = min(65535, raw.count - position)
            let final: UInt8 = position + count == raw.count ? 1 : 0
            zlib.append(final)
            zlib.append(UInt8(count & 0xff)); zlib.append(UInt8(count >> 8))
            zlib.append(UInt8(~count & 0xff)); zlib.append(UInt8((~count >> 8) & 0xff))
            zlib.append(contentsOf: raw[position..<(position + count)])
            position += count
        } while position < raw.count
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in raw { a = (a + UInt32(byte)) % 65521; b = (b + a) % 65521 }
        appendBig(&zlib, (b << 16) | a)
        var png: [UInt8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
        var header: [UInt8] = []
        appendBig(&header, UInt32(width)); appendBig(&header, UInt32(height))
        header.append(contentsOf: [8, 6, 0, 0, 0]) // 8-bit RGBA
        chunk(&png, "IHDR", header)
        chunk(&png, "IDAT", zlib)
        chunk(&png, "IEND", [])
        return Data(png)
    }
    private static func appendBig(_ bytes: inout [UInt8], _ value: UInt32) {
        bytes.append(contentsOf: [UInt8(value >> 24), UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
    }
    private static let table: [UInt32] = (0..<256).map { n in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 != 0 ? 0xedb88320 ^ (c >> 1) : c >> 1 }
        return c
    }
    private static func chunk(_ png: inout [UInt8], _ type: String, _ data: [UInt8]) {
        appendBig(&png, UInt32(data.count))
        let body = Array(type.utf8) + data
        png.append(contentsOf: body)
        var crc: UInt32 = 0xffffffff
        for byte in body { crc = table[Int((crc ^ UInt32(byte)) & 0xff)] ^ (crc >> 8) }
        appendBig(&png, crc ^ 0xffffffff)
    }
}
