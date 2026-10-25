import Foundation
import CoreFoundation

enum NetworkFailure: Error, LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
}

let staticExitRules = [
    "DOMAIN,localhost,DIRECT", "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", "IP-CIDR6,::/0,REJECT,no-resolve",
    "NETWORK,UDP,REJECT", "MATCH,静态IP出口"
]
// 未选择静态 IP：国外 TCP 以选定中转节点为出口，其余规则与静态出口模式一致。
let relayOnlyRules = Array(staticExitRules.dropLast()) + ["MATCH,静态IP机场中转"]

private func policyFailure(_ message: String = "配置包含不支持的字段或无效值。") -> NetworkFailure { .message(message) }
private func cleanString(_ value: Any?, max: Int = 8192, empty: Bool = true) -> Bool {
    guard let value = value as? String, value.utf8.count <= max, empty || !value.isEmpty else { return false }
    return !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
}
private func integer(_ value: Any?, range: ClosedRange<Int>) -> Int? {
    guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
          let number = Int(value.stringValue), range.contains(number) else { return nil }
    return number
}
private func boolean(_ value: Any) -> Bool { guard let value = value as? NSNumber else { return false }; return CFGetTypeID(value) == CFBooleanGetTypeID() }
private func stringList(_ value: Any?, max: Int = 32, itemMax: Int = 1024) -> Bool {
    guard let list = value as? [Any], list.count <= max else { return false }
    return list.allSatisfy { cleanString($0, max: itemMax) }
}

// 一次延迟测试最多覆盖的节点数与同时进行的探测数；单节点超时 5 秒。
let nodeDelayMaxNames = 256
let nodeDelayConcurrency = 16
let nodeDelayTimeoutMilliseconds = 5000

// 延迟探测只接受已由服务规范化并正在运行的机场节点，不能探测组或指定外部 URL。
func validatedNodeDelayNames(_ request: [String: Any], active: [String: Any]?) throws -> [String] {
    guard Set(request.keys) == Set(["op", "names"]), request["op"] as? String == "node_delays",
          let names = request["names"] as? [String], (1...nodeDelayMaxNames).contains(names.count),
          Set(names).count == names.count,
          names.allSatisfy({ cleanString($0, max: 512, empty: false) }) else {
        throw policyFailure("延迟测试需要 1 至 \(nodeDelayMaxNames) 个不同的有效节点。")
    }
    guard let proxies = active?["proxies"] as? [[String: Any]] else {
        throw policyFailure("请先连接，再测试节点延迟。")
    }
    let excluded: Set<String> = ["静态IP出口", "静态IP机场中转", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]
    let groups = Set((active?["proxy-groups"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String })
    let available = Set(proxies.compactMap { node -> String? in
        guard let name = node["name"] as? String, node["dialer-proxy"] == nil,
              !excluded.contains(name), !groups.contains(name) else { return nil }
        return name
    })
    guard names.allSatisfy(available.contains) else {
        throw policyFailure("只能测试当前连接订阅中的机场节点。")
    }
    return names
}

func nodeDelayPath(_ name: String) -> String {
    // 按 UTF-8 字节编码整个路径段；连点号也编码，防止 ..、斜杠或查询字符改变路由。
    let encoded = name.utf8.map { byte -> String in
        if (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || [45, 95, 126].contains(byte) {
            return String(UnicodeScalar(byte))
        }
        return String(format: "%%%02X", byte)
    }.joined()
    return "/proxies/" + encoded + "/delay?url=http%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=\(nodeDelayTimeoutMilliseconds)"
}

// 丢弃内核错误正文，只返回稳定状态；服务端原始错误可能含节点地址。
func nodeDelayResult(name: String, data: Data, httpStatus: Int, exitCode: Int32) -> [String: Any] {
    if exitCode == 28 || httpStatus == 504 { return ["name": name, "status": "timeout"] }
    guard exitCode == 0, httpStatus == 200,
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let delay = integer(json["delay"], range: 1...nodeDelayTimeoutMilliseconds) else {
        return ["name": name, "status": "error"]
    }
    return ["name": name, "status": "ok", "delay_ms": delay]
}
private func headers(_ value: Any, arrays: Bool) -> Bool {
    guard let values = value as? [String: Any], values.count <= 64 else { return false }
    let tokens = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~")
    return values.allSatisfy { name, value in
        !name.isEmpty && name.utf8.count <= 256 && name.unicodeScalars.allSatisfy(tokens.contains) &&
        (cleanString(value) || (arrays && stringList(value, max: 16, itemMax: 8192)))
    }
}
private func validateTransport(_ key: String, _ value: Any) throws {
    let allowed: [String: Set<String>] = [
        "reality-opts": ["public-key", "short-id"], "ech-opts": ["enable", "config", "query-server-name"],
        "ws-opts": ["path", "headers", "max-early-data", "early-data-header-name", "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"],
        "grpc-opts": ["grpc-service-name"], "http-opts": ["method", "path", "headers"], "h2-opts": ["host", "path"]
    ]
    guard let values = value as? [String: Any], let keys = allowed[key], Set(values.keys).isSubset(of: keys) else { throw policyFailure("订阅节点的传输选项不受支持。") }
    for (field, value) in values {
        switch field {
        case "headers": guard headers(value, arrays: key == "http-opts") else { throw policyFailure() }
        case "host": guard stringList(value, max: 32) else { throw policyFailure() }
        case "path":
            guard cleanString(value) || (key == "http-opts" && stringList(value, max: 32, itemMax: 8192)) else { throw policyFailure() }
        case "enable", "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open": guard boolean(value) else { throw policyFailure() }
        case "max-early-data": guard integer(value, range: 0...65536) != nil else { throw policyFailure() }
        default: guard cleanString(value, max: 16384) else { throw policyFailure() }
        }
    }
}

// 高权限服务仅接受结构化节点数据；全部路由、DNS、监听和文件位置在此重建。
// 不能把客户端 YAML 的剩余字段透传给以 root 身份运行的内核。
func restrictedConfiguration(_ input: [String: Any]) throws -> [String: Any] {
    let allowed: Set<String> = ["mixed-port", "allow-lan", "bind-address", "external-controller", "secret", "mode", "ipv6", "log-level", "find-process-mode", "geodata-mode", "geo-auto-update", "tcp-concurrent", "unified-delay", "profile", "tun", "dns", "proxies", "proxy-groups", "rules"]
    let safeToken = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    guard Set(input.keys).isSubset(of: allowed), let token = input["secret"] as? String,
          (32...128).contains(token.utf8.count), token.unicodeScalars.allSatisfy(safeToken.contains),
          let proxies = input["proxies"] as? [[String: Any]], (1...3000).contains(proxies.count),
          let rules = input["rules"] as? [String], rules == staticExitRules || rules == relayOnlyRules,
          let groups = input["proxy-groups"] as? [[String: Any]], groups.count == 1,
          Set(groups[0].keys) == Set(["name", "type", "proxies"]),
          groups[0]["name"] as? String == "静态IP机场中转", groups[0]["type"] as? String == "select",
          let choices = groups[0]["proxies"] as? [String], choices.count == 1 else {
        throw policyFailure("配置不符合静态出口服务的范围。")
    }
    let types: Set<String> = ["ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "socks5", "http"]
    let strings: Set<String> = ["name", "type", "server", "password", "username", "uuid", "cipher", "sni", "servername", "client-fingerprint", "fingerprint", "network", "flow", "encryption", "packet-encoding", "dialer-proxy", "obfs", "obfs-password", "auth", "auth-str", "ports", "mport", "congestion-controller", "udp-relay-mode"]
    let bools: Set<String> = ["udp", "tls", "skip-cert-verify", "disable-sni", "reduce-rtt"]
    let numbers: Set<String> = ["alterId", "heartbeat-interval", "hop-interval", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"]
    let transports: Set<String> = ["ws-opts", "grpc-opts", "h2-opts", "http-opts", "reality-opts", "ech-opts"]
    let keys = strings.union(bools).union(numbers).union(transports).union(["port", "alpn", "up", "down"])
    var names = Set<String>()
    var normalized: [[String: Any]] = []
    for node in proxies {
        guard Set(node.keys).isSubset(of: keys), let name = node["name"] as? String,
              cleanString(name, max: 512, empty: false), names.insert(name).inserted,
              !["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "静态IP机场中转"].contains(name),
              let type = node["type"] as? String, types.contains(type),
              let server = node["server"] as? String, cleanString(server, max: 253, empty: false),
              !server.contains(where: { $0.isWhitespace || "/@\\".contains($0) }),
              let port = integer(node["port"], range: 1...65535) else {
            throw policyFailure("订阅节点包含不支持的字段或无效地址。")
        }
        for (key, value) in node {
            if strings.contains(key) { guard cleanString(value) else { throw policyFailure() } }
            else if bools.contains(key) { guard boolean(value) else { throw policyFailure() } }
            else if numbers.contains(key) { guard integer(value, range: 0...Int(Int32.max)) != nil else { throw policyFailure() } }
            else if transports.contains(key) { try validateTransport(key, value) }
            else if key == "alpn" { guard stringList(value, itemMax: 256) else { throw policyFailure() } }
            else if key == "up" || key == "down" { guard cleanString(value, max: 32) || integer(value, range: 0...Int(Int32.max)) != nil else { throw policyFailure() } }
        }
        var clean = node; clean["port"] = port
        if name == "静态IP出口" {
            guard ["socks5", "http"].contains(type), node["dialer-proxy"] as? String == "静态IP机场中转" else { throw policyFailure("静态出口必须通过选定机场中转。") }
            clean["udp"] = false
        } else if node["dialer-proxy"] != nil { throw policyFailure("中转节点不能再指定外部代理链。") }
        normalized.append(clean)
    }
    let relayOnly = rules == relayOnlyRules
    guard names.contains("静态IP出口") != relayOnly else { throw policyFailure("配置不符合静态出口服务的范围。") }
    guard choices[0] != "静态IP出口", names.contains(choices[0]) else { throw policyFailure("中转节点不存在。") }
    let dns: [String: Any] = [
        "enable": true, "listen": "127.0.0.1:17895", "ipv6": false,
        "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": ["*.lan", "*.local", "localhost"], "respect-rules": true,
        "default-nameserver": ["223.5.5.5"], "nameserver": ["https://1.1.1.1/dns-query"],
        "proxy-server-nameserver": ["https://223.5.5.5/dns-query#DIRECT"],
        "nameserver-policy": ["geosite:cn": ["https://223.5.5.5/dns-query#DIRECT"]]
    ]
    return [
        "external-controller-unix": networkServiceRoot + "/runtime/controller.sock", "secret": token,
        "mixed-port": 17896, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule",
        "ipv6": false, "find-process-mode": "off", "geo-auto-update": false, "geodata-mode": false, "tcp-concurrent": true, "unified-delay": true,
        "log-level": "silent", "profile": ["store-selected": false, "store-fake-ip": false],
        "tun": ["enable": true, "device": "utun78", "stack": "mixed", "auto-route": true,
                // macOS 默认不注册系统 DNS；显式使用临时 resolver，避免浏览器继续查询局域网 DNS。
                "auto-detect-interface": true, "strict-route": true, "dns-hijack": ["any:53", "tcp://any:53"], "dns-mode": "native"] as [String: Any],
        "dns": dns, "proxies": normalized, "proxy-groups": groups, "rules": relayOnly ? relayOnlyRules : staticExitRules
    ]
}
