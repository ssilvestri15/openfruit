# Delta validation plan

The included fixtures are the Interface Builder source files supplied for the Delta investigation.

## 1. Build OpenIB

```powershell
.\scripts\build.ps1
.\scripts\test.ps1
```

## 2. Analyze source coverage

```powershell
.\build\Release\openib.exe analyze .\tests\fixtures\delta\LaunchScreen.storyboard
.\build\Release\openib.exe analyze .\tests\fixtures\delta\Main.storyboard
.\build\Release\openib.exe analyze .\tests\fixtures\delta\PauseMenu.storyboard
.\build\Release\openib.exe analyze .\tests\fixtures\delta\Settings.storyboard
```

Do not interpret zero unknown XML tags as full semantic support: a known tag can still contain properties OpenIB has not mapped yet.

## 3. Compile fixtures

```powershell
.\scripts\compile-delta.ps1
```

## 4. Inspect Apple output

From the extracted official app:

```powershell
$openib = ".\build\Release\openib.exe"
$official = "%USERPROFILE%\Downloads\Delta-official\Payload\Delta.app"

& $openib dump "$official\Base.lproj\LaunchScreen.storyboardc\UIViewController-dkK-ii-Bx4.nib" > official-controller.txt
& $openib dump "$official\Base.lproj\LaunchScreen.storyboardc\dkK-ii-Bx4-view-8Uu-wz-ps8.nib" > official-view.txt
```

Inspect the generated versions similarly and diff the textual dumps.

## 5. Runtime experiment

Do not replace every storyboard at once. Start with LaunchScreen only. If the app reaches the main storyboard-loading crash, LaunchScreen compatibility is proven separately from Main.

Then replace `Main.storyboardc` and iterate on the first UIKit decoding exception.

Every bundle modification must happen before the final application signing step, or the app must be re-signed afterwards.
