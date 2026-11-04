#pragma once

namespace OpenFruit {

class CompilerProxy {
public:
    static bool IsActive();
    static int Run(int argc, char* argv[]);
};

} // namespace OpenFruit
