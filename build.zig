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
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);

    const simtest_step = b.step("simtest", "Abstract RS mesh (simnet-parity); same binary as test");
    simtest_step.dependOn(&run_lib_tests.step);

    const run_stress = b.addRunArtifact(lib_tests);
    run_stress.setEnvironmentVariable("ZIG_ETHP2P_STRESS", "1");
    run_stress.has_side_effects = true;
    const stress_step = b.step("test-stress", "Run tests with ZIG_ETHP2P_STRESS=1 (longer RS mesh)");
    stress_step.dependOn(&run_stress.step);
}
