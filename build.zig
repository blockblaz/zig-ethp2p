const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zig_ethp2p", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "zig_ethp2p",
        .root_module = mod,
    });
    b.installArtifact(lib);

    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
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

    const broadcast_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ci_root_broadcast.zig"),
            .target = ci_target,
            .optimize = ci_opt,
            .sanitize_thread = ci_tsan,
        }),
    });
    const run_broadcast_tests = b.addRunArtifact(broadcast_tests);
    run_broadcast_tests.has_side_effects = true;
    const test_broadcast_step = b.step("test-broadcast", "Wire + layer + broadcast tests (ethp2p broadcast/ parity; TSan ≈ go -race)");
    test_broadcast_step.dependOn(&run_broadcast_tests.step);

    const sim_rs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ci_root_sim_rs.zig"),
            .target = ci_target,
            .optimize = ci_opt,
            .sanitize_thread = ci_tsan,
        }),
    });
    const run_sim_rs = b.addRunArtifact(sim_rs_tests);
    run_sim_rs.has_side_effects = true;
    const test_sim_rs_step = b.step("test-sim-rs", "RS abstract mesh tests (ethp2p sim RS simnet job parity; TSan)");
    test_sim_rs_step.dependOn(&run_sim_rs.step);

    const sim_gs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ci_root_sim_gossipsub.zig"),
            .target = ci_target,
            .optimize = ci_opt,
            .sanitize_thread = ci_tsan,
        }),
    });
    const run_sim_gs = b.addRunArtifact(sim_gs_tests);
    run_sim_gs.has_side_effects = true;
    const test_sim_gs_step = b.step("test-sim-gossipsub", "Gossipsub sim tests (ethp2p sim Gossipsub job parity; TSan)");
    test_sim_gs_step.dependOn(&run_sim_gs.step);

    const run_stress_ci = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = ci_target,
            .optimize = ci_opt,
            .sanitize_thread = ci_tsan,
        }),
    });
    const run_stress_ci_run = b.addRunArtifact(run_stress_ci);
    run_stress_ci_run.setEnvironmentVariable("ZIG_ETHP2P_STRESS", "1");
    run_stress_ci_run.has_side_effects = true;
    const stress_ci_step = b.step("test-stress-ci", "Full suite + ZIG_ETHP2P_STRESS (for main-only large-network job; TSan)");
    stress_ci_step.dependOn(&run_stress_ci_run.step);
}
