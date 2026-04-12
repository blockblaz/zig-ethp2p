const std = @import("std");

fn addZquicQuicModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) struct { quic_shim: *std.Build.Module, zquic: *std.Build.Module } {
    const zquic_pkg = b.dependency("zquic", .{ .target = target, .optimize = optimize });
    const zquic_mod = zquic_pkg.module("zquic");

    const quic_shim = b.addModule("quic", .{
        .root_source_file = b.path("src/transport/zquic_quic_shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_shim.addImport("zquic", zquic_mod);

    return .{ .quic_shim = quic_shim, .zquic = zquic_mod };
}

fn wireModule(m: *std.Build.Module, quic_shim: *std.Build.Module) void {
    m.addImport("quic", quic_shim);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    if (target.result.os.tag == .windows) {
        std.debug.panic("zig-ethp2p does not support Windows targets (zquic QUIC stack is tested on Unix).", .{});
    }

    const bundle = addZquicQuicModule(b, target, optimize);

    const mod = b.addModule("zig_ethp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    wireModule(mod, bundle.quic_shim);

    const lib = b.addLibrary(.{
        .name = "zig_ethp2p",
        .root_module = mod,
    });
    b.installArtifact(lib);

    const lib_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    wireModule(lib_tests_mod, bundle.quic_shim);
    const lib_tests = b.addTest(.{ .root_module = lib_tests_mod });
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

    // --- CI splits ---
    const ci_target = target;
    const ci_opt: std.builtin.OptimizeMode = .Debug;
    const ci_tsan = true;

    const bundle_ci = addZquicQuicModule(b, ci_target, ci_opt);

    const broadcast_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/ci_root_broadcast.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireModule(broadcast_tests_mod, bundle_ci.quic_shim);
    const broadcast_tests = b.addTest(.{ .root_module = broadcast_tests_mod });
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
    wireModule(sim_rs_tests_mod, bundle_ci.quic_shim);
    const sim_rs_tests = b.addTest(.{ .root_module = sim_rs_tests_mod });
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
    wireModule(sim_gs_tests_mod, bundle_ci.quic_shim);
    const sim_gs_tests = b.addTest(.{ .root_module = sim_gs_tests_mod });
    const run_sim_gs = b.addRunArtifact(sim_gs_tests);
    run_sim_gs.has_side_effects = true;
    const test_sim_gs_step = b.step("test-sim-gossipsub", "Gossipsub sim tests (ethp2p sim Gossipsub simnet job parity; TSan)");
    test_sim_gs_step.dependOn(&run_sim_gs.step);

    const stress_ci_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireModule(stress_ci_mod, bundle_ci.quic_shim);
    const run_stress_ci = b.addTest(.{ .root_module = stress_ci_mod });
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
    wireModule(quic_ci_mod, bundle_ci.quic_shim);
    const quic_ci_tests = b.addTest(.{ .root_module = quic_ci_mod });
    const run_quic_ci = b.addRunArtifact(quic_ci_tests);
    const test_quic_step = b.step("test-quic", "Transport QUIC tests (zquic handshake + stream framing)");
    test_quic_step.dependOn(&run_quic_ci.step);
}
