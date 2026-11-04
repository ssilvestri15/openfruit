let integerKey = PackStore.Key(17)
let textKey = PackStore.Key("before")
let first = PackStore.values(integerKey, textKey)
precondition(first.0 == 17 && first.1 == "before")
integerKey.value = 23
textKey.value = "after"
let second = PackStore.values(integerKey, textKey)
precondition(second.0 == 23 && second.1 == "after")
let empty: () = PackStore.values()
print("PASS: heterogeneous packs, mutable subscript reads, nested capture, empty pack")
