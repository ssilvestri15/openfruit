#include "operation_adapter.hpp"
#include <windows.h>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace OpenFruit;

void Require(bool cond, const char* msg) {
    if (!cond) throw std::runtime_error(msg);
}

int main() {
    try {
        BuildContext ctx{};
        ctx.repository_root = std::filesystem::current_path();

        OperationAdapterOptions options;
        options.pipe_name = L"openfruit-test-adapter-" + std::to_wstring(GetCurrentProcessId());

        OperationAdapter adapter(ctx, options);
        std::string err;
        Require(adapter.Start(err), ("Failed to start adapter: " + err).c_str());
        Require(adapter.IsRunning(), "Adapter should be running");

        // Test 1: Ping / Status
        {
            auto req = JsonValue::ObjectValue();
            req.Set("command", JsonValue::String("ping"));

            JsonValue resp;
            std::string call_err;
            bool ok = OperationAdapter::Call(adapter.PipeName(), req, resp, call_err);
            Require(ok, ("Call ping failed: " + call_err).c_str());
            Require(resp.GetString("status") == "ok", "Expected status ok");
            Require(resp.Get("running") && resp.Get("running")->Bool(), "Expected running true");
        }

        // Test 2: Devices command
        {
            auto req = JsonValue::ObjectValue();
            req.Set("command", JsonValue::String("devices"));

            JsonValue resp;
            std::string call_err;
            bool ok = OperationAdapter::Call(adapter.PipeName(), req, resp, call_err);
            Require(ok, ("Call devices failed: " + call_err).c_str());
            Require(resp.GetString("status") == "ok", "Expected status ok");
            Require(resp.Get("devices") && resp.Get("devices")->IsArray(), "Expected devices array");
        }

        // Test 3: Unknown command
        {
            auto req = JsonValue::ObjectValue();
            req.Set("command", JsonValue::String("invalid_action_xyz"));

            JsonValue resp;
            std::string call_err;
            bool ok = OperationAdapter::Call(adapter.PipeName(), req, resp, call_err);
            Require(ok, ("Call invalid failed: " + call_err).c_str());
            Require(resp.GetString("status") == "error", "Expected status error for unknown action");
        }

        // Test 4: Clean Stop
        adapter.Stop();
        Require(!adapter.IsRunning(), "Adapter should be stopped");

        std::cout << "Operation adapter IPC and named-pipe lifecycle tests passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << "\n";
        return 1;
    }
}
