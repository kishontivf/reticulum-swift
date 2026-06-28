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
//  Disabled (a pure no-op) until `configure(directory:)` is called, so release
//  and test builds that never configure it pay nothing. Call sites should still
//  guard expensive snapshot building with `if NetworkLog.isEnabled`.
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
