const std = @import("std");

fn linkOpenSslNonWindows(step: *std.Build.Step.Compile, resolved_target: std.Build.ResolvedTarget) void {
    if (resolved_target.result.os.tag == .windows) return;
    step.linkLibC();
    // Homebrew: pkg-config for both libssl and libcrypto repeats the same `-rpath .../openssl@3/.../lib`.
    // dyld aborts on duplicate LC_RPATH (often mistaken for a hang). Use pkg-config only for ssl;
    // link libcrypto by name so symbols resolve without a second identical rpath entry.
    switch (resolved_target.result.os.tag) {
        .driverkit, .ios, .macos, .tvos, .visionos, .watchos => {
            step.root_module.linkSystemLibrary("ssl", .{});
            step.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no });
        },
        else => {
            step.linkSystemLibrary("ssl");
            step.linkSystemLibrary("crypto");
        },
    }
}

fn wireZigEthP2pModule(
    m: *std.Build.Module,
    zig_opts_mod: *std.Build.Module,
    quic_mod: ?*std.Build.Module,
) void {
    m.addImport("zig_ethp2p_options", zig_opts_mod);
    if (quic_mod) |qm| m.addImport("quic", qm);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const enable_quic = b.option(bool, "enable-quic", "Link OpenSSL + devnw/quic (real listen/dial)") orelse false;

    if (enable_quic and target.result.os.tag == .windows) {
        std.debug.panic("-Denable-quic is unsupported on Windows in this repository (OpenSSL layout differs from non-Windows).", .{});
    }

    const zig_opts = b.addOptions();
    zig_opts.addOption(bool, "enable_quic", enable_quic);
    const zig_opts_mod = zig_opts.createModule();

    const quic_dep = if (enable_quic) b.dependency("quic", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    const quic_mod = if (quic_dep) |qd| qd.module("quic") else null;

    const mod = b.addModule("zig_ethp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    wireZigEthP2pModule(mod, zig_opts_mod, quic_mod);

    const lib = b.addLibrary(.{
        .name = "zig_ethp2p",
        .root_module = mod,
    });
    if (enable_quic) linkOpenSslNonWindows(lib, target);

    b.installArtifact(lib);

    const lib_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    wireZigEthP2pModule(lib_tests_mod, zig_opts_mod, quic_mod);
    const lib_tests = b.addTest(.{
        .root_module = lib_tests_mod,
    });
    if (enable_quic) linkOpenSslNonWindows(lib_tests, target);
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library tests (full suite, same as local dev)");
    test_step.dependOn(&run_lib_tests.step);

    const simtest_step = b.step("simtest", "Abstract RS mesh (simnet-parity); same binary as test");
    simtest_step.dependOn(&run_lib_tests.step);

    const run_stress = b.addRunArtifact(lib_tests);
    run_stress.setEnvironmentVariable("ZIG_ETHP2P_STRESS", "1");
    run_stress.has_side_effects = true;
    const stress_step = b.step("test-stress", "Run tests with ZIG_ETHP2P_STRESS=1 (longer RS mesh, 8-/16-node rings)");
    stress_step.dependOn(&run_stress.step);

    // --- CI splits (mirror https://github.com/ethp2p/ethp2p/blob/main/.github/workflows/ci.yml) ---
    const ci_target = target;
    const ci_opt: std.builtin.OptimizeMode = .Debug;
    const ci_tsan = true;

    const quic_dep_ci = if (enable_quic) b.dependency("quic", .{
        .target = ci_target,
        .optimize = ci_opt,
    }) else null;
    const quic_mod_ci = if (quic_dep_ci) |qd| qd.module("quic") else null;

    const broadcast_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/ci_root_broadcast.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireZigEthP2pModule(broadcast_tests_mod, zig_opts_mod, quic_mod_ci);
    const broadcast_tests = b.addTest(.{
        .root_module = broadcast_tests_mod,
    });
    if (enable_quic) linkOpenSslNonWindows(broadcast_tests, ci_target);
    const run_broadcast_tests = b.addRunArtifact(broadcast_tests);
    run_broadcast_tests.has_side_effects = true;
    const test_broadcast_step = b.step("test-broadcast", "Wire + layer + broadcast tests (ethp2p broadcast/ parity; TSan ≈ go -race)");
    test_broadcast_step.dependOn(&run_broadcast_tests.step);

    const sim_rs_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/ci_root_sim_rs.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireZigEthP2pModule(sim_rs_tests_mod, zig_opts_mod, quic_mod_ci);
    const sim_rs_tests = b.addTest(.{
        .root_module = sim_rs_tests_mod,
    });
    if (enable_quic) linkOpenSslNonWindows(sim_rs_tests, ci_target);
    const run_sim_rs = b.addRunArtifact(sim_rs_tests);
    run_sim_rs.has_side_effects = true;
    const test_sim_rs_step = b.step("test-sim-rs", "RS abstract mesh tests (ethp2p sim RS simnet job parity; TSan)");
    test_sim_rs_step.dependOn(&run_sim_rs.step);

    const sim_gs_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/ci_root_sim_gossipsub.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireZigEthP2pModule(sim_gs_tests_mod, zig_opts_mod, quic_mod_ci);
    const sim_gs_tests = b.addTest(.{
        .root_module = sim_gs_tests_mod,
    });
    if (enable_quic) linkOpenSslNonWindows(sim_gs_tests, ci_target);
    const run_sim_gs = b.addRunArtifact(sim_gs_tests);
    run_sim_gs.has_side_effects = true;
    const test_sim_gs_step = b.step("test-sim-gossipsub", "Gossipsub sim tests (ethp2p sim Gossipsub job parity; TSan)");
    test_sim_gs_step.dependOn(&run_sim_gs.step);

    const stress_ci_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireZigEthP2pModule(stress_ci_mod, zig_opts_mod, quic_mod_ci);
    const run_stress_ci = b.addTest(.{
        .root_module = stress_ci_mod,
    });
    if (enable_quic) linkOpenSslNonWindows(run_stress_ci, ci_target);
    const run_stress_ci_run = b.addRunArtifact(run_stress_ci);
    run_stress_ci_run.setEnvironmentVariable("ZIG_ETHP2P_STRESS", "1");
    run_stress_ci_run.has_side_effects = true;
    const stress_ci_step = b.step("test-stress-ci", "Full suite + ZIG_ETHP2P_STRESS (for main-only large-network job; TSan)");
    stress_ci_step.dependOn(&run_stress_ci_run.step);

    const quic_ci_mod = b.createModule(.{
        .root_source_file = b.path("src/ci_root_quic.zig"),
        .target = ci_target,
        .optimize = ci_opt,
    });
    wireZigEthP2pModule(quic_ci_mod, zig_opts_mod, quic_mod_ci);
    const quic_ci_tests = b.addTest(.{
        .root_module = quic_ci_mod,
    });
    // TLS + QUIC stacks are deep; default test thread stack has been marginal on macOS (SIGKILL under load).
    quic_ci_tests.stack_size = 32 * 1024 * 1024;
    if (enable_quic) linkOpenSslNonWindows(quic_ci_tests, ci_target);
    const run_quic_ci = b.addRunArtifact(quic_ci_tests);
    run_quic_ci.has_side_effects = true;
    const test_quic_step = b.step("test-quic", "Transport QUIC tests (-Denable-quic; OpenSSL). Real handshake tests skip on macOS (devnw/quic + Zig Mutex issue); Linux CI runs them.");
    test_quic_step.dependOn(&run_quic_ci.step);
}
