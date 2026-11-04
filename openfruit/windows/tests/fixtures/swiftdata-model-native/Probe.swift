import SwiftData

// The original SDK declaration resolves this to
// SwiftDataMacros.PersistentModelMacro. No generated expansion is provided.
@Model
final class ModelRecord {
    var title: String

    init(title: String) {
        self.title = title
    }
}

// Require the conformance synthesized by the original macro, rather than only
// accepting that the annotation was parsed or the plugin was loaded.
private func requirePersistentModel<T: PersistentModel>(_ model: T) {}

@main
struct SwiftDataModelMain {
    static func main() {
        let record = ModelRecord(title: "OPENFRUIT original SwiftData macro")
        requirePersistentModel(record)
        precondition(record.title == "OPENFRUIT original SwiftData macro")
    }
}
