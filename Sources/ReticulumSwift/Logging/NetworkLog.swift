//
//  NetworkLog.swift
//  ReticulumSwift
//
//  Opt-in, file-backed diagnostic log for *following routing*: the path-table
//  snapshot after every announce, and the per-packet message-direction decision
//  (HEADER_2 routed vs HEADER_1 direct vs no-path broadcast).
//
//  It is deliberately separate from the unified `os.Logger` firehose so a human
//  can read just the announce store / routing story in one file. It is also
//  separate from the host app's own debug log — point it at its own file
//  (e.g. `reticulum-network.log`).
//
//  Off unless the environment asks for it: `configure(directory:)` no-ops unless
//  `RETICULUM_NETWORK_LOG` is set (see `environmentKey`), so a normal run — release
//  or debug — opens no file and pays nothing. A test harness turns the whole thing
//  on by launching the app with that variable set. Call sites should still guard
//  expensive snapshot building with `if NetworkLog.isEnabled`.
//
//  [TEMPORARY] The whole type is field-test scaffolding. Erasing it later is meant
//  to be one grep: `NetworkLog.` for the sinks, `[TEMPORARY]` for the call sites,
//  and the single `environmentKey` line in the host's UI-test launch defaults.
//

import Foundation

public enum NetworkLog {
    /// Active log file, or nil when disabled. Written/read only on `queue`,
    /// except the cheap `isEnabled` read (a benign racy pointer check).
    nonisolated(unsafe) private static var fileURL: URL?
    private static let queue = DispatchQueue(label: "net.reticulum.NetworkLog")

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone.current
        return formatter
    }()

    /// Enable the log, writing to `<directory>/<fileName>`. The previous session's
    /// file is rolled aside to `*.prev.<fileName>`-style `reticulum-network.prev.log`
    /// first (one generation) so an immediate process relaunch can't discard it —
    /// the same hazard the host app's file log guards against.
    public static func configure(directory: URL, fileName: String = "reticulum-network.log") {
        // Opt-in: without the environment flag this is the only cost the log ever has.
        guard isEnabledInEnvironment else { return }
        let url = directory.appendingPathComponent(fileName)
        let prevName = (fileName as NSString).deletingPathExtension + ".prev."
            + (fileName as NSString).pathExtension
        let prevURL = directory.appendingPathComponent(prevName)
        queue.sync {
            if FileManager.default.fileExists(atPath: url.path) {
                try? FileManager.default.removeItem(at: prevURL)
                try? FileManager.default.moveItem(at: url, to: prevURL)
            }
            let header = "=== Reticulum network log — "
                + DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .medium)
                + " ===\n"
            try? header.data(using: .utf8)?.write(to: url, options: .atomic)
            fileURL = url
        }
    }

    /// Turn the log off (subsequent calls are no-ops).
    public static func disable() {
        queue.sync { fileURL = nil }
    }

    /// Whether a destination is configured. Cheap; guard snapshot building with this.
    public static var isEnabled: Bool { fileURL != nil }

    /// Environment variable that turns the network log on. Set it to `1`/`true`/`yes` in the
    /// launched process — `UITestLaunchDefaults` does this for every UI test — and both
    /// `configure(directory:)` and `debugScaffolding` come up enabled. Anything else, including
    /// absent, leaves the log off end to end.
    public static let environmentKey = "RETICULUM_NETWORK_LOG"

    /// Resolved once, on first use. A `let` rather than a re-read per call so the value can't
    /// change under a running session and cost a `ProcessInfo` lookup on every log line.
    private static let isEnabledInEnvironment: Bool = {
        switch ProcessInfo.processInfo.environment[environmentKey]?.lowercased() {
        case "1", "true", "yes": return true
        default: return false
        }
    }()

    /// Master switch for the TEMPORARY debug scaffolding added while finalising
    /// transport switching (the `[MSG]` / `[ROUTE] HEADER_2` / `[ANNDROP]` / `[RECORD]` /
    /// `[FALLBACK] register` / `[ANNOUNCE] emit|interval` markers, emitted via `debug(_:)`).
    /// Flip to `false` to silence them all in one place without touching the call sites;
    /// they're slated for removal once the offline/return behaviour is signed off.
    ///
    /// The mobility/field-test round adds, under the same switch. Every one of these call sites
    /// carries a `// [TEMPORARY]` comment, so `grep -rn '\[TEMPORARY\]'` across the four repos
    /// lists exactly what has to come out:
    ///   - `[TX]`     — transmit failures and silent no-interface drops (ReticulumTransport)
    ///   - `[TXSTAT]` — rolling per-interface packet/byte tally, one line per 10s
    ///   - `[IFACE]`  — interface state transitions, with time held in the previous state
    ///   - `[QUEUE]`  — LXMF outbound queue census, slow/blocking attempts, enqueue/dequeue
    ///   - `[LINK]`   — LXMF link establishment outcome and duration
    ///   - `[RES]`    — LXMF resource (image) transfer lifecycle and throughput
    ///   - `[PROOF]`  — delivery proof, with end-to-end age and attempt count
    ///   - `[NET]` / `[APP]` / `[SEND]` — host-app reachability, lifecycle and send intent
    ///
    /// Defaults to whatever `environmentKey` says; settable at runtime to silence (or force) the
    /// markers without touching call sites. Forcing it on without the environment flag writes
    /// nothing on its own — `configure` will not have opened a file.
    nonisolated(unsafe) public static var debugScaffolding = isEnabledInEnvironment

    /// Append a line ONLY when both the log is configured and `debugScaffolding` is on. Used for
    /// the temporary diagnostic markers so they can be toggled/removed via the single flag above.
    public static func debug(_ message: @autoclosure () -> String) {
        guard debugScaffolding else { return }
        log(message())
    }

    /// [TEMPORARY] A visually distinct banner line, for correlating the log against events that
    /// happen outside the process — "walked out of WiFi range", "put the phone away".
    /// A field session produces thousands of lines; `grep '>>>'` finds the handful a
    /// human caused, which is what the rest of the timeline has to be read against.
    public static func mark(_ message: @autoclosure () -> String) {
        debug(">>> \(message())")
    }

    /// [TEMPORARY] Elapsed milliseconds since a monotonic start instant, e.g. `"1043ms"`.
    ///
    /// Monotonic (`ContinuousClock`) rather than `Date`, because these durations are
    /// read to decide whether something *blocked* — and a wall-clock delta silently
    /// absorbs NTP steps and the clock jumps that follow a radio/coverage change,
    /// which is precisely when we're measuring.
    public static func ms(since start: ContinuousClock.Instant) -> String {
        let elapsed = ContinuousClock.now - start
        return "\(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)ms"
    }

    /// [TEMPORARY] Byte count in the shortest readable unit, e.g. `"237.4KB"`. Sized payloads are
    /// the difference between a text message and an image, which take entirely
    /// different paths (single packet vs. Resource transfer).
    public static func bytes(_ count: Int) -> String {
        if count < 1024 { return "\(count)B" }
        if count < 1024 * 1024 { return String(format: "%.1fKB", Double(count) / 1024) }
        return String(format: "%.2fMB", Double(count) / (1024 * 1024))
    }

    /// [TEMPORARY] Transfer rate over a monotonic interval, e.g. `"219.8KB/s"`. Returns `"—"` for a
    /// zero-length interval rather than dividing by zero.
    public static func rate(_ count: Int, since start: ContinuousClock.Instant) -> String {
        let seconds = Double((ContinuousClock.now - start).components.seconds)
            + Double((ContinuousClock.now - start).components.attoseconds) / 1e18
        guard seconds > 0.001 else { return "—" }
        return "\(bytes(Int(Double(count) / seconds)))/s"
    }

    /// One-line summary of a path entry for snapshots. An all-zero `nextHop` is
    /// rendered as `ZERO` (not `direct`) so a degenerate/null next hop is obvious
    /// versus a genuinely direct (nil) one.
    public static func describe(_ entry: PathEntry) -> String {
        let dest = hex8(entry.destinationHash)
        let nextHop: String
        if let nh = entry.nextHop {
            nextHop = nh.allSatisfy { $0 == 0 } ? "ZERO(\(nh.count)B)" : hex8(nh)
        } else {
            nextHop = "direct"
        }
        let state: String
        switch entry.pathState {
        case 1: state = "unresponsive"
        case 2: state = "responsive"
        default: state = "unknown"
        }
        let name = entry.displayName.map { " name=\"\(sanitize($0))\"" } ?? ""
        let expired = entry.isExpired ? " EXPIRED" : ""
        return "dest=\(dest) hops=\(entry.hopCount) iface=\(entry.interfaceId) nextHop=\(nextHop) state=\(state)\(name)\(expired)"
    }

    /// First 8 bytes of a hash as hex (the conventional short form).
    public static func hex8(_ data: Data) -> String {
        data.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// True when this entry's next hop is a null/all-zero hash (degenerate — it
    /// can't actually route). Distinct from a nil next hop, which means "direct".
    public static func hasZeroNextHop(_ entry: PathEntry) -> Bool {
        guard let nh = entry.nextHop else { return false }
        return nh.allSatisfy { $0 == 0 }
    }

    /// Strip control/non-printable scalars so a node's self-chosen display name
    /// can't turn the log file into "binary" (some carry stray bytes).
    private static func sanitize(_ raw: String) -> String {
        String(String.UnicodeScalarView(raw.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7f }))
    }

    /// Append one timestamped line (a multi-line message is fine — it's written verbatim).
    public static func log(_ message: @autoclosure () -> String) {
        guard isEnabled else { return }
        let stamp = dateFormatter.string(from: Date())
        let line = "\(stamp) \(message())\n"
        queue.async {
            guard let url = fileURL, let data = line.data(using: .utf8) else { return }
            if let handle = try? FileHandle(forWritingTo: url) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            } else {
                try? data.write(to: url, options: .atomic)
            }
        }
    }
}
