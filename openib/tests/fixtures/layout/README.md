# Independent Interface Builder layout probes

These small, OpenIB-owned storyboards isolate two unresolved UIKit archive
semantics. They are not copies of Delta scenes and their OpenIB output is **not**
a reference for the expected values.

- `TextLayoutProbe.storyboard` varies text, width, and system/monospaced font
  while keeping the other text-view properties fixed. Compare the encoded
  `UITextView.UIContentSize` values in its view NIB.
- `TableFooterProbe.storyboard` varies the source footer Y coordinate and the
  table style. Compare the footer label's encoded center in the three view
  NIBs. If `ibtool` rejects an empty static section list, record that error
  before modifying the fixture and keep the variants otherwise identical.

On a Mac with Xcode selected, from this directory:

```sh
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-version
xcrun ibtool --version
xcrun ibtool --compile TextLayoutProbe.storyboardc TextLayoutProbe.storyboard
xcrun ibtool --compile TableFooterProbe.storyboardc TableFooterProbe.storyboard
```

Preserve the command output, Xcode/SDK versions, the two resulting
`.storyboardc` directories, and the exact input files together. Compare
decoded NIB object graphs against OpenIB using `openib diff` or the existing
comparison tooling; do not interpret byte ordering or a single matching
application value as a general layout rule. An independent UIKit runtime
measurement may also help distinguish compile-time archiving from layout at
launch.
