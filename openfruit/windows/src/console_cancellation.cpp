#include "console_cancellation.hpp"
#include <windows.h>
#include <thread>
#include <stdexcept>
namespace OpenFruit {
namespace {
struct Registration { OperationContextPtr context; HANDLE requested = nullptr; };
SRWLOCK registration_lock = SRWLOCK_INIT;
Registration* active = nullptr;
BOOL WINAPI OnControl(DWORD type) {
    if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT) return FALSE;
    AcquireSRWLockShared(&registration_lock);
    const bool handled = active != nullptr;
    if (active && !active->context->control->cancellation_requested.exchange(true)) SetEvent(active->requested);
    ReleaseSRWLockShared(&registration_lock);
    return handled ? TRUE : FALSE;
}
}
struct ConsoleCancellation::Impl {
    Registration registration;
    HANDLE stop = nullptr;
    std::thread worker;
    bool installed = false;
    explicit Impl(OperationContextPtr context) {
        if (!context || !context->control) throw std::invalid_argument("Console cancellation requires operation control");
        registration.context = std::move(context);
        if (!GetConsoleCP()) return; // Headless invocation: do not allocate/attach a console.
        registration.requested = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!registration.requested || !stop) { Finish(); throw std::runtime_error("Unable to create console cancellation controls"); }
        AcquireSRWLockExclusive(&registration_lock);
        if (active) {
            ReleaseSRWLockExclusive(&registration_lock); Finish();
            throw std::runtime_error("A console operation boundary is already active");
        }
        if (!SetConsoleCtrlHandler(OnControl, TRUE)) {
            ReleaseSRWLockExclusive(&registration_lock); Finish();
            throw std::runtime_error("Unable to register console cancellation handler");
        }
        active = &registration; installed = true;
        ReleaseSRWLockExclusive(&registration_lock);
        try {
            worker = std::thread([this] {
                HANDLE events[] = {registration.requested, stop};
                if (WaitForMultipleObjects(2, events, FALSE, INFINITE) == WAIT_OBJECT_0)
                    registration.context->Emit("operation.cancelling");
            });
        } catch (...) { Finish(); throw; }
    }
    void Finish() noexcept {
        if (installed) {
            AcquireSRWLockExclusive(&registration_lock);
            active = nullptr;
            SetConsoleCtrlHandler(OnControl, FALSE);
            installed = false;
            ReleaseSRWLockExclusive(&registration_lock);
        }
        if (stop) SetEvent(stop);
        if (worker.joinable()) worker.join();
        if (registration.requested) { CloseHandle(registration.requested); registration.requested = nullptr; }
        if (stop) { CloseHandle(stop); stop = nullptr; }
    }
    ~Impl() { Finish(); }
};
ConsoleCancellation::ConsoleCancellation(OperationContextPtr context) : impl_(std::make_unique<Impl>(std::move(context))) {}
ConsoleCancellation::~ConsoleCancellation() = default;
void ConsoleCancellation::Finish() noexcept { if (impl_) impl_->Finish(); }
}
