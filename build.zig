const std = @import("std");

const QuicLinkBundle = struct {
    quic_mod: *std.Build.Module,
    lsquic_lib: *std.Build.Step.Compile,
    ssl_lib: *std.Build.Step.Compile,
    crypto_lib: *std.Build.Step.Compile,
};

fn addLsquicQuicModule(
    b: *std.Build,
    lsquic_pkg: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) QuicLinkBundle {
    const nested = lsquic_pkg.builder;
    const boringssl_dep = nested.dependency("boringssl", .{
        .target = target,
        .optimize = optimize,
    });
    const lsquic_upstream = nested.dependency("lsquic", .{
        .target = target,
        .optimize = optimize,
    });
    const openssl_src = boringssl_dep.builder.dependency("ssl", .{});

    const quic_mod = b.addModule("quic", .{
        .root_source_file = b.path("src/transport/lsquic_quic_shim.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    quic_mod.addIncludePath(lsquic_upstream.path("include"));
    quic_mod.addIncludePath(openssl_src.path("include"));
    // zig-ethp2p extension header (lsquic_ethp2p_ext.h) lives alongside the vendor build.zig.
    quic_mod.addIncludePath(b.path("vendor/lsquic_zig"));

    return .{
        .quic_mod = quic_mod,
        .lsquic_lib = lsquic_pkg.artifact("lsquic"),
        .ssl_lib = boringssl_dep.artifact("ssl"),
        .crypto_lib = boringssl_dep.artifact("crypto"),
    };
}

fn linkQuicLibs(
    step: *std.Build.Step.Compile,
    bundle: QuicLinkBundle,
    resolved_target: std.Build.ResolvedTarget,
) void {
    step.linkLibC();
    step.linkLibrary(bundle.lsquic_lib);
    step.linkLibrary(bundle.ssl_lib);
    step.linkLibrary(bundle.crypto_lib);
    const zlib_name: []const u8 = if (resolved_target.result.os.tag == .windows) "zlib1" else "z";
    step.linkSystemLibrary(zlib_name);
    if (resolved_target.result.os.tag != .windows) {
        step.linkSystemLibrary("pthread");
        step.linkSystemLibrary("m");
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

    const enable_quic = b.option(bool, "enable-quic", "Build lsquic + BoringSSL in-repo QUIC shim (listen/dial)") orelse false;

    if (enable_quic and target.result.os.tag == .windows) {
        std.debug.panic("-Denable-quic is unsupported on Windows in this repository (lsquic_zig build is non-Windows focused).", .{});
    }

    const zig_opts = b.addOptions();
    zig_opts.addOption(bool, "enable_quic", enable_quic);
    const zig_opts_mod = zig_opts.createModule();

    const quic_bundle: ?QuicLinkBundle = if (enable_quic) addLsquicQuicModule(
        b,
        b.dependency("lsquic_zig", .{ .target = target, .optimize = optimize }),
        target,
        optimize,
    ) else null;
    const quic_mod = if (quic_bundle) |qb| qb.quic_mod else null;

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
    if (quic_bundle) |qb| linkQuicLibs(lib, qb, target);

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
    if (quic_bundle) |qb| linkQuicLibs(lib_tests, qb, target);
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

    const quic_bundle_ci: ?QuicLinkBundle = if (enable_quic) addLsquicQuicModule(
        b,
        b.dependency("lsquic_zig", .{ .target = ci_target, .optimize = ci_opt }),
        ci_target,
        ci_opt,
    ) else null;
    const quic_mod_ci = if (quic_bundle_ci) |qb| qb.quic_mod else null;

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
    if (quic_bundle_ci) |qb| linkQuicLibs(broadcast_tests, qb, ci_target);
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
    if (quic_bundle_ci) |qb| linkQuicLibs(sim_rs_tests, qb, ci_target);
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
    if (quic_bundle_ci) |qb| linkQuicLibs(sim_gs_tests, qb, ci_target);
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
    wireZigEthP2pModule(stress_ci_mod, zig_opts_mod, quic_mod_ci);
    const run_stress_ci = b.addTest(.{
        .root_module = stress_ci_mod,
    });
    if (quic_bundle_ci) |qb| linkQuicLibs(run_stress_ci, qb, ci_target);
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
    if (quic_bundle_ci) |qb| linkQuicLibs(quic_ci_tests, qb, ci_target);
    const run_quic_ci = b.addRunArtifact(quic_ci_tests);
    const test_quic_step = b.step("test-quic", "Transport QUIC tests (use with -Denable-quic; lsquic + BoringSSL)");
    test_quic_step.dependOn(&run_quic_ci.step);
}
