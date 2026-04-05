const std = @import("std");

// Everything is always built: BoringSSL (libssl + libcrypto) for lsquic's
// TLS 1.3 QUIC handshake, and lsquic for QUIC transport.
//
// Discovery-layer crypto (secp256k1, ECDSA, ECDH) uses std.crypto only —
// no BoringSSL headers are needed outside of lsquic_quic_shim.zig.
//
// lsquic_zig does not support Windows builds; panic early on that target.
const LsquicBundle = struct {
    quic_mod: *std.Build.Module,
    lsquic_lib: *std.Build.Step.Compile,
    ssl_lib: *std.Build.Step.Compile,
    crypto_lib: *std.Build.Step.Compile,
    openssl_include: std.Build.LazyPath,
};

fn addLsquicBundle(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) LsquicBundle {
    const lsquic_pkg = b.dependency("lsquic_zig", .{ .target = target, .optimize = optimize });
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
    quic_mod.addIncludePath(b.path("vendor/lsquic_zig"));

    return .{
        .quic_mod = quic_mod,
        .lsquic_lib = lsquic_pkg.artifact("lsquic"),
        .ssl_lib = boringssl_dep.artifact("ssl"),
        .crypto_lib = boringssl_dep.artifact("crypto"),
        .openssl_include = openssl_src.path("include"),
    };
}

fn wireModule(m: *std.Build.Module, bundle: LsquicBundle) void {
    m.addImport("quic", bundle.quic_mod);
}

fn linkLibs(
    step: *std.Build.Step.Compile,
    bundle: LsquicBundle,
    resolved_target: std.Build.ResolvedTarget,
) void {
    step.linkLibC();
    step.linkLibrary(bundle.ssl_lib);
    step.linkLibrary(bundle.crypto_lib);
    step.linkLibrary(bundle.lsquic_lib);
    const zlib_name: []const u8 = if (resolved_target.result.os.tag == .windows) "zlib1" else "z";
    step.linkSystemLibrary(zlib_name);
    if (resolved_target.result.os.tag != .windows) {
        step.linkSystemLibrary("pthread");
        step.linkSystemLibrary("m");
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    if (target.result.os.tag == .windows) {
        std.debug.panic("zig-ethp2p does not support Windows targets (lsquic_zig build is non-Windows focused).", .{});
    }

    const bundle = addLsquicBundle(b, target, optimize);

    const mod = b.addModule("zig_ethp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    wireModule(mod, bundle);

    const lib = b.addLibrary(.{
        .name = "zig_ethp2p",
        .root_module = mod,
    });
    linkLibs(lib, bundle, target);
    b.installArtifact(lib);

    const lib_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    wireModule(lib_tests_mod, bundle);
    const lib_tests = b.addTest(.{ .root_module = lib_tests_mod });
    linkLibs(lib_tests, bundle, target);
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

    const bundle_ci = addLsquicBundle(b, ci_target, ci_opt);

    const broadcast_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/ci_root_broadcast.zig"),
        .target = ci_target,
        .optimize = ci_opt,
        .sanitize_thread = ci_tsan,
    });
    wireModule(broadcast_tests_mod, bundle_ci);
    const broadcast_tests = b.addTest(.{ .root_module = broadcast_tests_mod });
    linkLibs(broadcast_tests, bundle_ci, ci_target);
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
    wireModule(sim_rs_tests_mod, bundle_ci);
    const sim_rs_tests = b.addTest(.{ .root_module = sim_rs_tests_mod });
    linkLibs(sim_rs_tests, bundle_ci, ci_target);
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
    wireModule(sim_gs_tests_mod, bundle_ci);
    const sim_gs_tests = b.addTest(.{ .root_module = sim_gs_tests_mod });
    linkLibs(sim_gs_tests, bundle_ci, ci_target);
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
    wireModule(stress_ci_mod, bundle_ci);
    const run_stress_ci = b.addTest(.{ .root_module = stress_ci_mod });
    linkLibs(run_stress_ci, bundle_ci, ci_target);
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
    wireModule(quic_ci_mod, bundle_ci);
    const quic_ci_tests = b.addTest(.{ .root_module = quic_ci_mod });
    linkLibs(quic_ci_tests, bundle_ci, ci_target);
    const run_quic_ci = b.addRunArtifact(quic_ci_tests);
    const test_quic_step = b.step("test-quic", "Transport QUIC tests (lsquic + BoringSSL handshake + stream framing)");
    test_quic_step.dependOn(&run_quic_ci.step);
}
