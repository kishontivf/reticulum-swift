//
//  NetworkLogGateTests.swift
//  ReticulumSwiftTests
//
//  [TEMPORARY] Guards the opt-in gate on the field-test network log: it must stay OFF
//  unless `NetworkLog.environmentKey` is set in the process. The log writes an
//  unbounded file and every `[TEMPORARY]` marker in the transport, router and carriers
//  drains through it, so a default flip to "on" would ship that cost to users silently.
//  Goes away with the scaffolding it guards.
//

import XCTest
@testable import ReticulumSwift

final class NetworkLogGateTests: XCTestCase {
    /// The suite runs without the variable set, which is the case that matters: this is the
    /// state every non-test process is in.
    func testDisabledWhenEnvironmentVariableAbsent() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment[NetworkLog.environmentKey] == nil,
                          "\(NetworkLog.environmentKey) is set in this process — the gate is being asked for")

        XCTAssertFalse(NetworkLog.debugScaffolding,
                       "Debug scaffolding must default off; it is enabled only by the environment flag")

        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("NetworkLogGateTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        NetworkLog.configure(directory: directory)

        XCTAssertFalse(NetworkLog.isEnabled, "configure() must no-op without the environment flag")
        let contents = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(contents, [], "configure() must not create a log file when disabled")
    }
}
