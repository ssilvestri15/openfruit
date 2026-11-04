// OPENFRUIT regression probe: a package compiled for an older deployment target
// may declare a requirement that becomes obsolete on a later OS. The consuming
// application's Base SDK does not change the package's deployment target.
protocol AvailabilityBoundProtocol {
    @available(iOS, introduced: 16.0, obsoleted: 18.1)
    var value: Bool { get }
}

struct AvailabilityBoundConformance: AvailabilityBoundProtocol {
    @available(iOS, introduced: 16.0, obsoleted: 18.1)
    var value: Bool { true }
}
