// OPENFRUIT-owned compiler language probe. Not a macro/plugin substitute.
public class OwnedRoot {}
public class OwnedProjection<Root: OwnedRoot> {}
public struct OwnedQuery<Value> {}

public struct OwnedAccessor<Value> {
    private var storage: ((OwnedQuery<Value>) -> OwnedQuery<Bool>)?
    public var value: ((OwnedQuery<Value>) -> OwnedQuery<Bool>)? {
        @storageRestrictions(initializes: storage)
        init(initialValue) { storage = initialValue }
        get { storage }
        set { storage = newValue }
    }
    public init<Root: OwnedRoot>(_ type: Value.Type) where Value: OwnedProjection<Root> {
        self.value = nil
    }
}
