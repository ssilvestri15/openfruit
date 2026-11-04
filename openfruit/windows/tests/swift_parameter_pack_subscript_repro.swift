// OPENFRUIT compiler capability probe: this must compile without modifying a
// package that uses a parameter-pack expansion over a generic static subscript.
protocol OPENFRUITProbeSerializable {}

struct OPENFRUITProbeKey<Value: OPENFRUITProbeSerializable> {}

enum OPENFRUITProbeDefaults {
	static subscript<Value: OPENFRUITProbeSerializable>(
		_ key: OPENFRUITProbeKey<Value>
	) -> Value {
		get { fatalError("compile-only probe") }
		set {}
	}

	static func currentValues<each Value: OPENFRUITProbeSerializable>(
		_ keys: repeat OPENFRUITProbeKey<each Value>
	) -> (repeat each Value) {
		(repeat self[each keys])
	}

	static func nestedCurrentValues<each Value: OPENFRUITProbeSerializable>(
		_ keys: repeat OPENFRUITProbeKey<each Value>
	) -> () -> (repeat each Value) {
		{
			func getCurrentValues() -> (repeat each Value) {
				(repeat self[each keys])
			}

			return getCurrentValues()
		}
	}
}
