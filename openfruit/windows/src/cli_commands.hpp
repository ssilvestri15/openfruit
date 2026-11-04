#pragma once
#include <memory>
namespace OpenFruit { class EventJournal; }

// Argument parsing and human rendering only. Build execution is delegated to
// ApplicationService, shared with the operation adapter.
int RunCommand(int argc, char* argv[], std::shared_ptr<OpenFruit::EventJournal> journal = {});
