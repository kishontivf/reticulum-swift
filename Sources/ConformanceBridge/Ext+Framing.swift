// Ext+Framing.swift — conformance bridge extension cluster: M-FRAMING
//   hdlc_deframe         — strip HDLC framing + reverse byte-stuffing (single frame)
//   hdlc_deframe_stream  — RNS TCP/HDLC read-loop deframer (runt-drop + shared-FLAG)
//   kiss_deframe         — strip KISS framing + reverse TFEND/TFESC transpose (single)
//   kiss_deframe_stream  — RNS TCP/KISS read-loop deframer (port-nibble + non-DATA drop)
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_hdlc_deframe :1431, cmd_kiss_deframe :1461,
//  cmd_hdlc_deframe_stream :1595, cmd_kiss_deframe_stream :1608).
// Returns nil for any command it does not own (dispatch chain: Ext+Dispatch.swift).
//
// The single-frame commands mirror python's two sequential `bytes.replace()`
// un-stuffing calls exactly. The *_stream commands re-implement RNS's real
// TCPClientInterface.read_loop de-framing (TCPInterface.py:337-398) byte-for-byte
// — RNS exposes no standalone read-loop callable, and the swift library's
// HDLC/KISS.extractFrames helpers differ (no runt-drop, no shared-FLAG buffer
// retention, no KISS port-nibble strip / non-CMD_DATA ignore), so the loop is
// reproduced here to match python's delivered-frame list exactly.
import Foundation
import ReticulumSwift

// Left-to-right, non-overlapping byte-sequence replacement — mirrors python's
// `bytes.replace(old, new)` semantics exactly (used for the two-step un-stuffing).
private func framingReplaceAll(_ data: Data, _ find: [UInt8], _ replace: [UInt8]) -> Data {
    guard !find.isEmpty else { return data }
    let bytes = Array(data)
    let n = bytes.count
    let m = find.count
    var result = Data()
    result.reserveCapacity(n)
    var i = 0
    while i < n {
        if i + m <= n && Array(bytes[i..<(i + m)]) == find {
            result.append(contentsOf: replace)
            i += m
        } else {
            result.append(bytes[i])
            i += 1
        }
    }
    return result
}

func handleFramingExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Strip HDLC framing (FLAG + HDLC.escape(data) + FLAG) and reverse the
    // byte-stuffing: extract bytes between the first two FLAG (0x7E) delimiters,
    // then undo with the exact two replacements RNS's TCP read loop performs
    // (TCPInterface.py:389-391): ESC+(FLAG^MASK) -> FLAG, then ESC+(ESC^MASK) -> ESC.
    case "hdlc_deframe":
        let framed = Array(try getHex(p, "framed"))
        guard let start = framed.firstIndex(of: HDLC.FLAG) else {
            throw BridgeError.invalidData("no HDLC FLAG (0x7E) delimiter found in framed input")
        }
        guard let end = framed[(start + 1)...].firstIndex(of: HDLC.FLAG) else {
            throw BridgeError.invalidData("unterminated HDLC frame: only one FLAG delimiter")
        }
        var frame = Data(framed[(start + 1)..<end])
        frame = framingReplaceAll(frame, [HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK], [HDLC.FLAG])
        frame = framingReplaceAll(frame, [HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK], [HDLC.ESC])
        return ["data": hex(frame)]

    // Strip KISS framing (FEND + CMD_DATA + KISS.escape(data) + FEND): extract
    // bytes between the first two FEND (0xC0) delimiters, verify the leading
    // command byte is CMD_DATA (0x00), then reverse the transpose
    // FESC+TFEND -> FEND, then FESC+TFESC -> FESC.
    case "kiss_deframe":
        let framed = Array(try getHex(p, "framed"))
        guard let start = framed.firstIndex(of: KISS.FEND) else {
            throw BridgeError.invalidData("no KISS FEND (0xC0) delimiter found in framed input")
        }
        guard let end = framed[(start + 1)...].firstIndex(of: KISS.FEND) else {
            throw BridgeError.invalidData("unterminated KISS frame: only one FEND delimiter")
        }
        let inner = Array(framed[(start + 1)..<end])
        guard inner.count >= 1 else {
            throw BridgeError.invalidData("empty KISS frame: no command byte")
        }
        let kissCommand = inner[0]
        guard kissCommand == KISS.CMD_DATA else {
            // python: f"unexpected KISS command byte {command:#04x}, expected CMD_DATA ({KISS.CMD_DATA:#04x})"
            throw BridgeError.invalidData(
                "unexpected KISS command byte \(String(format: "0x%02x", Int(kissCommand))), expected "
                + "CMD_DATA (\(String(format: "0x%02x", Int(KISS.CMD_DATA))))"
            )
        }
        var payload = Data(inner[1...])
        payload = framingReplaceAll(payload, [KISS.FESC, KISS.TFEND], [KISS.FEND])
        payload = framingReplaceAll(payload, [KISS.FESC, KISS.TFESC], [KISS.FESC])
        return ["data": hex(payload)]

    // Deframe a TCP/HDLC byte stream through RNS's real read loop
    // (TCPInterface.py:381-398). Applies the runt-drop rule (frames whose
    // de-stuffed length <= HEADER_MINSIZE == 19 are silently dropped),
    // multi-frame extraction, and shared-FLAG buffer retention from one stream.
    case "hdlc_deframe_stream":
        let stream = Array(try getHex(p, "stream"))
        // RNS.Reticulum.HEADER_MINSIZE == 2+1+(TRUNCATED_HASHLENGTH//8) == 19.
        // (HW_MTU is read by python but is unused on the HDLC read path.)
        let headerMinSize = 2 + 1 + TRUNCATED_HASH_LENGTH
        var frames: [JSONValue] = []
        var frameBuffer = stream
        var flagsRemaining = true
        while flagsRemaining {
            guard let frameStart = frameBuffer.firstIndex(of: HDLC.FLAG) else {
                flagsRemaining = false
                break
            }
            guard let frameEnd = frameBuffer[(frameStart + 1)...].firstIndex(of: HDLC.FLAG) else {
                flagsRemaining = false
                break
            }
            var frame = Data(frameBuffer[(frameStart + 1)..<frameEnd])
            frame = framingReplaceAll(frame, [HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK], [HDLC.FLAG])
            frame = framingReplaceAll(frame, [HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK], [HDLC.ESC])
            if frame.count > headerMinSize {
                frames.append(hex(frame))
            }
            // Shared-FLAG retention: keep the closing FLAG as the next opener.
            frameBuffer = Array(frameBuffer[frameEnd...])
        }
        return ["frames": .array(frames)]

    // Deframe a TCP/KISS byte stream through RNS's real read loop
    // (TCPInterface.py:349-378, kiss_framing path). The leading byte's port
    // nibble is stripped (command = byte & 0x0F, so 0x10/0x20 are accepted as
    // CMD_DATA) and frames whose command != CMD_DATA are silently ignored.
    case "kiss_deframe_stream":
        let stream = Array(try getHex(p, "stream"))
        let hwMtu = getIntOptional(p, "hw_mtu") ?? 262144
        // LIBRARY-GAP: swift KISS enum has no CMD_UNKNOWN sentinel (python reads
        // KISS.CMD_UNKNOWN == 0xFE from RNS KISSInterface; only RNodeConstants
        // exposes it). Mirrored locally — any non-CMD_DATA value is behaviorally
        // equivalent ("command not yet decoded").
        let cmdUnknown: UInt8 = 0xFE
        var frames: [JSONValue] = []
        var inFrame = false
        var escape = false
        var kissCommand: UInt8 = cmdUnknown
        var dataBuffer = Data()
        var pointer = 0
        while pointer < stream.count {
            var byte = stream[pointer]
            pointer += 1
            if inFrame && byte == KISS.FEND && kissCommand == KISS.CMD_DATA {
                inFrame = false
                frames.append(hex(dataBuffer))
            } else if byte == KISS.FEND {
                inFrame = true
                kissCommand = cmdUnknown
                dataBuffer = Data()
            } else if inFrame && dataBuffer.count < hwMtu {
                if dataBuffer.count == 0 && kissCommand == cmdUnknown {
                    // Strip the port nibble (only one HDLC port supported).
                    byte = byte & 0x0F
                    kissCommand = byte
                } else if kissCommand == KISS.CMD_DATA {
                    if byte == KISS.FESC {
                        escape = true
                    } else {
                        if escape {
                            if byte == KISS.TFEND { byte = KISS.FEND }
                            if byte == KISS.TFESC { byte = KISS.FESC }
                            escape = false
                        }
                        dataBuffer.append(byte)
                    }
                }
            }
        }
        return ["frames": .array(frames)]

    default:
        return nil
    }
}
