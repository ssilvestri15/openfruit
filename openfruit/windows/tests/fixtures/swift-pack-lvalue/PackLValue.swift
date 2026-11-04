public enum PackStore {
    public final class Key<Value> {
        public var value: Value
        public init(_ value: Value) { self.value = value }
    }
    public static subscript<Value>(key: Key<Value>) -> Value {
        get { key.value }
        set { key.value = newValue }
    }
    public static func values<each Value>(_ keys: repeat Key<each Value>) -> (repeat each Value) {
        func current() -> (repeat each Value) {
            (repeat self[each keys])
        }
        return current()
    }
}
