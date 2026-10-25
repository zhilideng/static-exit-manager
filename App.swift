import SwiftUI
import Security

private func writeJSON(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value) {
        FileHandle.standardOutput.write(data)
    }
}

if CommandLine.arguments.contains("--keychain") {
    do {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        guard let request = try JSONSerialization.jsonObject(with: input) as? [String: String],
              let id = request["id"], !id.isEmpty else {
            throw CocoaError(.coderInvalidValue)
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "StaticExitManager",
            kSecAttrAccount as String: id
        ]
        var result: [String: Any]
        switch request["action"] {
        case "delete":
            let status = SecItemDelete(query as CFDictionary)
            result = ["ok": status == errSecSuccess || status == errSecItemNotFound]
        case "set":
            let value = Data((request["password"] ?? "").utf8)
            var status = SecItemUpdate(query as CFDictionary, [kSecValueData: value] as CFDictionary)
            if status == errSecItemNotFound {
                var item = query
                item[kSecValueData as String] = value
                status = SecItemAdd(item as CFDictionary, nil)
            }
            result = ["ok": status == errSecSuccess]
        case "get":
            var item = query
            item[kSecReturnData as String] = true
            item[kSecMatchLimit as String] = kSecMatchLimitOne
            var value: CFTypeRef?
            let status = SecItemCopyMatching(item as CFDictionary, &value)
            result = ["ok": status == errSecSuccess,
                      "password": (value as? Data).flatMap { String(data: $0, encoding: .utf8) } ?? ""]
        default:
            result = ["ok": false, "error": "未知钥匙串操作。"]
        }
        writeJSON(result)
    } catch {
        writeJSON(["ok": false, "error": "钥匙串请求格式无效。"])
    }
    exit(0)
}

if CommandLine.arguments.contains("--service") {
    do {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let request = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CocoaError(.coderInvalidValue)
        }
        writeJSON(serviceRequest(request))
    } catch {
        writeJSON(["ok": false, "error": "网络服务请求格式无效。"])
    }
    exit(0)
}

if CommandLine.arguments.contains("--service-status") {
    writeJSON(serviceRequest(["op": "status"]))
    exit(0)
}

struct ExitProfile: Identifiable, Decodable {
    var id: String
    var `protocol`: String
    var name: String
    var server: String
    var port: Int
    var username: String
    var expected: String
    var expired: String
    var address: String { "\(server):\(port)" }
    var expiryLabel: String { expired.isEmpty ? "未填写" : String(expired.prefix(10)) }
}

struct Subscription: Identifiable, Decodable {
    var uid: String
    var name: String
    var current: Bool?
    var usage: SubscriptionUsage?
    var id: String { uid }
}

struct SubscriptionUsage: Decodable {
    var used_bytes: Int64?
    var total_bytes: Int64?
    var expires_at: Int64?
    var status: String
    var source: String?
    var fetched_at: String?
    var reason: String?

    static func bytesLabel(_ bytes: Int64?) -> String {
        guard let bytes, bytes >= 0 else { return "未提供" }
        if bytes == 0 { return "0 B" }
        let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
        var value = Double(bytes), index = 0
        while value >= 1024 && index < units.count - 1 { value /= 1024; index += 1 }
        return String(format: index == 0 ? "%.0f %@" : "%.2f %@", value, units[index])
    }
    var usedLabel: String { Self.bytesLabel(used_bytes) }
    var totalLabel: String { Self.bytesLabel(total_bytes) }
    var expiryLabel: String {
        guard let expires_at, expires_at > 0 else { return "未提供期限" }
        let date = Date(timeIntervalSince1970: Double(expires_at))
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let suffix = date < Date() ? (status == "stale" ? " · 待核实" : " · 已到期") : ""
        return formatter.string(from: date) + suffix
    }
    var fullExpiryLabel: String {
        guard let expires_at, expires_at > 0 else { return "服务商未提供期限" }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm zzz"
        return formatter.string(from: Date(timeIntervalSince1970: Double(expires_at)))
    }
    var fraction: Double? {
        guard let used_bytes, let total_bytes, total_bytes > 0 else { return nil }
        return min(max(Double(used_bytes) / Double(total_bytes), 0), 1)
    }
    var snapshotLabel: String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = fetched_at.flatMap { formatter.date(from: $0) ?? ISO8601DateFormatter().date(from: $0) }
        let time = date.map { $0.formatted(date: .abbreviated, time: .shortened) }
        if status == "stale" { return "历史数据" + (time.map { " · \($0)" } ?? "") }
        if let time { return "更新于 \(time)" }
        return "尚无用量数据"
    }
}

private func backendReply(_ request: [String: Any]) async -> [String: Any] {
    guard let data = try? JSONSerialization.data(withJSONObject: request),
          let executable = Bundle.main.executableURL?.path,
          let resources = Bundle.main.resourceURL else {
        return ["ok": false, "error": "无法读取应用后台，请重新安装完整应用。"]
    }
    let backend = resources.appendingPathComponent("backend.py").path
    // 使用应用内置的独立 Python；-I 隔离本机环境变量和用户包，-B 不在应用包内写缓存以免破坏签名。
    let python = resources.appendingPathComponent("python/bin/python3")
    let response = await Task.detached { () -> Data in
        let task = Process()
        task.executableURL = python
        task.arguments = ["-I", "-B", backend, executable]
        let input = Pipe(), output = Pipe()
        task.standardInput = input
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            input.fileHandleForWriting.write(data)
            try? input.fileHandleForWriting.close()
            let value = output.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            return value
        } catch {
            return Data("{\"ok\":false,\"error\":\"无法启动应用内置的 Python，请重新安装完整应用。\"}".utf8)
        }
    }.value
    return (try? JSONSerialization.jsonObject(with: response)) as? [String: Any]
        ?? ["ok": false, "error": "后台响应异常，请刷新后重试。"]
}

struct NodeDelay: Decodable {
    let status: String
    let delay_ms: Int?
    let tested_at: String

    // 后台每 10 分钟刷新，只展示最近一次结果，不再标记过期。
    var label: String {
        status == "ok" ? "\(delay_ms ?? 0) ms" : (status == "timeout" ? "超时" : "失败")
    }
    var testedTime: String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: tested_at) ?? ISO8601DateFormatter().date(from: tested_at) else { return "未知" }
        return date.formatted(date: .omitted, time: .standard)
    }
}

struct ExitLocation: Decodable {
    let ip: String
    let status: String
    let country: String
    let country_code: String
    let region: String
    let city: String
    let source: String
    let fetched_at: String

    var label: String {
        guard ["ok", "stale"].contains(status) else { return "地点暂不可用" }
        let localizedCountry = Locale(identifier: "zh_Hans_CN").localizedString(forRegionCode: country_code)
        let parts = [country_code.isEmpty ? country : (localizedCountry ?? country), region, city]
        var unique: [String] = []
        for part in parts where !part.isEmpty && !unique.contains(part) { unique.append(part) }
        return unique.isEmpty ? "地点暂不可用" : unique.joined(separator: " · ")
    }

    var help: String {
        var value = "IP 归属地由 ipwho.is 提供，可能与实际机房位置不同。只查询实测出口 IP，不发送代理账号或密码。"
        if status == "stale" { value += " 当前为历史缓存，暂未能更新。" }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: fetched_at) ?? ISO8601DateFormatter().date(from: fetched_at) {
            value += " 查询于 " + date.formatted(date: .abbreviated, time: .shortened) + "。"
        }
        return value
    }
}

@MainActor final class Model: ObservableObject {
    @Published var profiles: [ExitProfile] = []
    @Published var selected: String?
    @Published var subscriptions: [Subscription] = []
    @Published var subscriptionUID = ""
    @Published var subscription = "尚未选择订阅"
    @Published var nodes: [String] = []
    @Published var nodeDelays: [String: NodeDelay] = [:]
    @Published var testingLatencies = false
    @Published var latencyProgress = ""
    @Published var usageMessage = ""
    @Published var testingNodeNames: Set<String> = []
    private var latencyTask: Task<Void, Never>?
    private var latencySchedule: Task<Void, Never>?
    private var latencyKickoff: Task<Void, Never>?
    private var lastBackgroundLatency: Date?
    @Published var relay = ""
    @Published var activeRelay = ""
    /// 当前保存（连接中即正在使用）的静态 IP；用于区分用户改选与刷新回填。
    private var activeProfileID = ""
    @Published var configuredServer = ""
    @Published var configuredPort = 0
    @Published var exitIP = ""
    @Published var verifiedAt: Date?
    @Published var exitLocation: ExitLocation?
    @Published var loadingExitLocation = false
    private var locationTask: Task<Void, Never>?
    private var locationRequestID = UUID()
    private var deferredCheckTask: Task<Void, Never>?
    private var prewarmTask: Task<Void, Never>?
    @Published var checking = false
    @Published var busy = false
    @Published var activity = ""
    @Published var message = ""
    @Published var error = false
    @Published var tun = false
    @Published var running = false
    @Published var stateKnown = false
    @Published var serviceError = ""
    @Published var recoveryNeeded = false
    @Published var migrated = false
    @Published var serviceStatus = serviceRegistrationStatus()
    @Published var hasBackup = false

    var selectedProfile: ExitProfile? { profiles.first { $0.id == selected } }
    var selectedSubscription: Subscription? { subscriptions.first { $0.uid == subscriptionUID } }
    var serviceReady: Bool { serviceStatus == "enabled" }
    var prewarmKey: String { (selected ?? "") + "\n" + relay }
    var shouldOfferStop: Bool { running || !stateKnown || recoveryNeeded }
    var connectionVerified: Bool { running && stateKnown && tun && !exitIP.isEmpty && verifiedAt != nil && !error }
    var serviceLabel: String {
        if serviceReady { return "网络服务已启用" }
        return "网络服务尚未安装"
    }

    func refreshServiceStatus() {
        serviceStatus = serviceRegistrationStatus()
    }

    func registerService() {
        guard !busy else { return }
        busy = true
        message = "请在系统弹窗中输入管理员密码，安装网络服务…"
        error = false
        Task {
            // 管理员授权弹窗会等待用户输入，放到后台避免界面卡住。
            let result = await Task.detached { registerNetworkService() }.value
            busy = false
            refreshServiceStatus()
            error = result["ok"] as? Bool != true
            message = result[error ? "error" : "message"] as? String ?? "网络服务安装结果未知，请刷新。"
            if !error { load(verify: false) }
        }
    }

    func load(verify: Bool = true) {
        // 主动刷新或重新打开时才追加实测；连接事务已返回本次验证结果。
        refreshServiceStatus()
        call(["op": "status"]) { ok in
            if ok && verify && self.running && self.stateKnown && !self.recoveryNeeded { self.call(["op": "verify"]) }
            if ok {
                self.prewarm()
                self.startLatencySchedule()
                self.requestBackgroundLatency()
            }
        }
    }

    func nodeDelayLabel(_ name: String) -> String {
        if testingNodeNames.contains(name) { return "测速中…" }
        return nodeDelays[name]?.label ?? "未测"
    }

    /// 已连接时选中另一个中转节点即切换过去，无需再点「应用所选出口」；后端事务验证出口，失败自动恢复原节点。
    /// 未连接时只记住选择，仍由用户点「开始连接」接管网络。
    func chooseRelay(_ name: String) {
        guard running, stateKnown, !recoveryNeeded, !busy, name != activeRelay, let id = selected else { return }
        call(["op": "switch", "id": id, "relay": name])
    }

    /// 已连接时在静态 IP 列表中改选另一条，即沿用当前中转切换到该静态出口；失败自动恢复原出口。
    /// 未连接时只改变选择，仍由用户点「开始连接」。
    func chooseProfile(_ id: String?) {
        guard running, stateKnown, !recoveryNeeded, !busy, let id, id != activeProfileID,
              profiles.contains(where: { $0.id == id }) else { return }
        let currentRelay = activeRelay.isEmpty ? relay : activeRelay
        guard !currentRelay.isEmpty else { return }
        call(["op": "switch", "id": id, "relay": currentRelay])
    }

    func nodeDelayHelp(_ name: String) -> String {
        guard let delay = nodeDelays[name] else { return "尚未测速；应用打开期间每 10 分钟自动测速。" }
        return "测试时间 " + delay.testedTime + "；应用打开期间每 10 分钟自动测速。"
    }

    func cancelLatencyTest() {
        latencyTask?.cancel()
        latencyTask = nil
        testingNodeNames = []
        latencyProgress = ""
        testingLatencies = false
        message = "已取消测速，保留已测结果。"
    }

    /// 一次请求测完所选节点（后端并发 16、单节点 5 秒）。后台测速静默进行，旧结果保留到新结果到达；
    /// 不占用 busy，连接、切换或停止会在后端中止它。
    func testNodeLatencies(onlySelected: Bool = false, background: Bool = false) {
        // 手动点击时恰有后台测速在跑：直接展示它的进度，不重复发起。
        if testingLatencies && !background && latencyProgress.isEmpty { latencyProgress = "正在测速…"; return }
        guard !busy, !testingLatencies, stateKnown, !recoveryNeeded, !subscriptionUID.isEmpty else { return }
        let uid = subscriptionUID
        var names = onlySelected ? nodes.filter { $0 == relay } : nodes
        // 当前中转排在最前，结果最先可用。
        if let index = names.firstIndex(of: relay) { names.insert(names.remove(at: index), at: 0) }
        guard !names.isEmpty else { return }
        testingLatencies = true
        if background {
            lastBackgroundLatency = Date()
        } else {
            testingNodeNames = Set(names)
            latencyProgress = onlySelected ? "正在测当前节点…" : "正在测全部 \(names.count) 个节点…"
            message = ""
        }
        latencyTask = Task {
            let result = await backendReply(["op": "node_delays", "subscription_uid": uid, "names": names])
            guard !Task.isCancelled else { return }
            testingNodeNames = []
            latencyProgress = ""
            testingLatencies = false
            latencyTask = nil
            guard uid == subscriptionUID else { return }
            if result["ok"] as? Bool == true, result["subscription_uid"] as? String == uid,
               let values: [String: NodeDelay] = decode(result["node_delays"]) {
                nodeDelays.merge(values) { _, new in new }
                if !background { message = "测速完成。" }
            } else if !background {
                message = result["error"] as? String ?? "节点延迟检测失败，请刷新后重试。"
            }
        }
    }

    /// 应用打开期间每 10 分钟后台测速一轮；关闭应用即停止，不安装常驻后台任务。
    private func startLatencySchedule() {
        guard latencySchedule == nil else { return }
        latencySchedule = Task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 600 * 1_000_000_000)
                testNodeLatencies(background: true)
            }
        }
    }

    /// 打开应用、换订阅、连接成功或出现未测节点时补测一轮；正在执行其它操作时稍后重试。
    private func requestBackgroundLatency() {
        if let last = lastBackgroundLatency, Date().timeIntervalSince(last) < 60 { return }
        latencyKickoff?.cancel()
        latencyKickoff = Task {
            for _ in 0..<40 {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                if Task.isCancelled { return }
                if !busy && !testingLatencies && stateKnown {
                    testNodeLatencies(background: true)
                    return
                }
            }
        }
    }

    func call(_ request: [String: Any], completion: ((Bool) -> Void)? = nil) {
        guard !busy else { completion?(false); return }
        let op = request["op"] as? String ?? ""
        busy = true
        checking = op == "verify"
        error = false
        let labels = [
            "status": "正在读取本机配置…", "select_subscription": "正在切换订阅…",
            "switch": running ? "正在验证并切换出口…" : "正在保存出口选择…",
            "verify": "正在验证静态出口、系统 DNS 与网页连接…", "import_current": "正在载入当前静态 IP…",
            "import": "正在导入静态 IP…", "save": "正在保存…", "restore": "正在恢复配置…",
            "delete": "正在删除记录…", "start": "正在启动网络连接并验证出口…",
            "stop": "正在停止网络连接…", "migrate": "正在迁移本机订阅和静态 IP…",
            "add_subscription": "正在下载订阅…", "import_subscription": "正在导入订阅…",
            "update_subscription": "正在更新订阅…", "delete_subscription": "正在删除订阅…"
        ]
        activity = labels[op] ?? "正在处理…"
        if ["verify", "start", "stop", "switch", "select_subscription", "restore"].contains(op) {
            clearExitVerification()
        }
        Task {
            let beganAt = ProcessInfo.processInfo.systemUptime
            let result = await backendReply(request)
            checking = false
            guard result["ok"] as? Bool == true else {
                let originalError = result["error"] as? String ?? "操作失败。"
                // 失败可能发生在内核已启动之后。重新取实际状态，不以操作前的布尔值判断连接。
                if op != "status" {
                    activity = "正在确认失败后的连接状态…"
                    let refreshed = await backendReply(["op": "status"])
                    if refreshed["ok"] as? Bool == true { apply(refreshed) }
                    else { markStateUnknown(refreshed["error"] as? String) }
                } else {
                    markStateUnknown(originalError)
                }
                refreshServiceStatus()
                message = originalError
                error = true
                busy = false
                completion?(false)
                return
            }
            apply(result)
            message = result["message"] as? String ?? ""
            if op == "start" {
                let elapsed = ProcessInfo.processInfo.systemUptime - beganAt
                message += String(format: " 本次连接用时 %.1f 秒。", elapsed)
                requestBackgroundLatency()
            }
            if !serviceError.isEmpty { error = true; if message.isEmpty { message = serviceError } }
            if recoveryNeeded { error = true; if message.isEmpty { message = "上次配置操作未完成，请停止连接后恢复管理。" } }
            busy = false
            completion?(true)
        }
    }

    private func markStateUnknown(_ reason: String?) {
        stateKnown = false
        clearExitVerification()
        serviceError = reason ?? "无法确认网络服务状态，请刷新或尝试停止连接。"
    }

    private func clearExitVerification() {
        exitIP = ""
        verifiedAt = nil
        locationRequestID = UUID()
        locationTask?.cancel()
        locationTask = nil
        deferredCheckTask?.cancel()
        deferredCheckTask = nil
        exitLocation = nil
        loadingExitLocation = false
    }

    private func runDeferredChecks(for ip: String) {
        deferredCheckTask?.cancel()
        let requestID = locationRequestID
        // TUN 出口与 DNS 接管已在连接事务中验证；代理端口与网页连通性在后台补测，失败只提示、不回滚。
        deferredCheckTask = Task {
            let result = await backendReply(["op": "deferred_checks"])
            guard !Task.isCancelled, locationRequestID == requestID, exitIP == ip,
                  running, stateKnown, verifiedAt != nil else { return }
            deferredCheckTask = nil
            guard let check = result["deferred_checks"] as? [String: Any], check["ip"] as? String == ip,
                  let status = check["status"] as? String, status != "ok" else { return }
            let detail = check["message"] as? String ?? ""
            if status == "failure" { error = true }
            message += (message.isEmpty ? "" : " ") + "连接后检测：" + (detail.isEmpty ? "未完成。" : detail)
        }
    }

    /// 打开应用或改选出口时预先完成内核校验，使首次「开始连接」命中校验缓存；不占用操作锁。
    func prewarm() {
        guard !running, stateKnown, !recoveryNeeded, let id = selected, !relay.isEmpty else { return }
        prewarmTask?.cancel()
        let request: [String: Any] = ["op": "prewarm", "id": id, "relay": relay]
        prewarmTask = Task { _ = await backendReply(request) }
    }

    private func loadExitLocation(for ip: String) {
        locationTask?.cancel()
        let requestID = UUID()
        locationRequestID = requestID
        exitLocation = nil
        loadingExitLocation = true
        // 地点是补充信息，独立查询，不占用连接操作或改变验证结果。
        locationTask = Task {
            let result = await backendReply(["op": "exit_location", "ip": ip])
            guard !Task.isCancelled, locationRequestID == requestID, exitIP == ip,
                  running, stateKnown, verifiedAt != nil else { return }
            if result["ok"] as? Bool == true,
               let value: ExitLocation = decode(result["location"]), value.ip == ip {
                exitLocation = value
            }
            loadingExitLocation = false
            locationTask = nil
        }
    }

    var currentUsage: SubscriptionUsage? { subscriptions.first { $0.uid == subscriptionUID }?.usage }

    func refreshSubscriptionUsage() {
        guard !busy, !subscriptionUID.isEmpty else { return }
        let uid = subscriptionUID
        busy = true
        usageMessage = ""
        activity = "正在读取订阅到期时间与流量…"
        Task {
            let result = await backendReply(["op": "refresh_subscription_usage", "uid": uid])
            if result["ok"] as? Bool == true, let values: [Subscription] = decode(result["subscriptions"]) {
                subscriptions = values
                usageMessage = result["message"] as? String ?? "订阅用量已刷新。"
            } else {
                usageMessage = result["error"] as? String ?? "用量获取失败，保留上次数据。"
            }
            busy = false
        }
    }

    private func apply(_ result: [String: Any]) {
        if let values: [ExitProfile] = decode(result["profiles"]) {
            profiles = values
            if !profiles.contains(where: { $0.id == selected }) { selected = profiles.first?.id }
        }
        if let values: [Subscription] = decode(result["subscriptions"]) { subscriptions = values }
        if let value = result["subscription_uid"] as? String {
            if value != subscriptionUID { nodeDelays = [:]; usageMessage = "" }
            subscriptionUID = value
        }
        if let values: [String: NodeDelay] = decode(result["node_delays"]) { nodeDelays = values }
        if !nodes.isEmpty && nodes.contains(where: { nodeDelays[$0] == nil }) { requestBackgroundLatency() }
        if let value = result["subscription"] as? String { subscription = value.isEmpty ? "尚未选择订阅" : value }
        if let value = result["tun"] as? Bool { tun = value }
        if let value = result["state_known"] as? Bool { stateKnown = value }
        if let value = result["running"] as? Bool, result["state_known"] as? Bool != false { running = value; stateKnown = true }
        if let value = result["service_error"] as? String { serviceError = value }
        if let value = result["recovery_needed"] as? Bool { recoveryNeeded = value }
        if let value = result["migrated"] as? Bool { migrated = value }
        if let value = result["service_status"] as? String, ["enabled", "notRegistered"].contains(value) { serviceStatus = value }
        if let value = result["backup"] as? Bool { hasBackup = value }
        if let values = result["nodes"] as? [String] {
            nodes = values
            activeRelay = result["relay"] as? String ?? ""
            relay = values.contains(activeRelay) ? activeRelay : (values.first ?? "")
        }
        if result["configured_exit"] is NSNull { configuredServer = ""; configuredPort = 0 }
        if let proxy = result["configured_exit"] as? [String: Any] {
            configuredServer = proxy["server"] as? String ?? ""
            configuredPort = proxy["port"] as? Int ?? 0
        }
        if let value = result["selected_profile_id"] as? String { activeProfileID = value }
        if let value = result["selected_id"] as? String, profiles.contains(where: { $0.id == value }) {
            selected = value
        }
        if let ip = result["ip"] as? String, !ip.isEmpty, running, stateKnown {
            exitIP = ip
            verifiedAt = Date()
            loadExitLocation(for: ip)
            if result["deferred_checks_pending"] as? Bool == true { runDeferredChecks(for: ip) }
        }
        if !running || !stateKnown { clearExitVerification() }
    }

    private func decode<T: Decodable>(_ object: Any?) -> T? {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
}

struct Pill: View {
    var title: String
    var symbol: String
    var color: Color = .secondary
    var body: some View {
        Label(title, systemImage: symbol).font(.system(size: 11, weight: .medium))
            .foregroundStyle(color).padding(.horizontal, 9).padding(.vertical, 5)
            .background(color.opacity(0.09), in: Capsule())
    }
}

struct ConnectionButtonStyle: ButtonStyle {
    var prominent = false
    var tint: Color = .blue
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .padding(.horizontal, 14).frame(height: 36)
            .foregroundStyle(prominent ? Color.white : Color.primary)
            .background(prominent ? tint : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(prominent ? Color.clear : Color.primary.opacity(0.12)))
            .overlay(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(configuration.isPressed ? 0.08 : 0)))
            .opacity(isEnabled ? 1 : 0.45)
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct SubscriptionRow: View {
    let item: Subscription
    let selected: Bool
    let canSelect: Bool
    let canDelete: Bool
    let connected: Bool
    let onSelect: () -> Void
    let onDelete: () -> Void
    @State private var hovered = false

    private var accessibilitySummary: String {
        let state = selected ? "当前订阅" : "点击选择"
        let used = item.usage?.usedLabel ?? "未提供"
        let total = item.usage?.totalLabel ?? "未提供"
        let expiry = item.usage?.expiryLabel ?? "未提供期限"
        let history = item.usage?.status == "stale" ? "，历史数据" : ""
        return "\(item.name)，\(state)，已用 \(used)，总量 \(total)，到期 \(expiry)\(history)"
    }

    var body: some View {
        HStack(alignment: .top, spacing: 4) {
            Button(action: onSelect) {
                VStack(alignment: .leading, spacing: 7) {
                    HStack(spacing: 5) {
                        Text(item.name).font(.system(size: 13, weight: selected ? .semibold : .medium))
                            .lineLimit(2).multilineTextAlignment(.leading)
                        if selected { Image(systemName: "checkmark.circle.fill").font(.system(size: 11)).foregroundStyle(.blue) }
                    }
                    Text("\(item.usage?.usedLabel ?? "未提供") / \(item.usage?.totalLabel ?? "未提供")")
                        .font(.system(size: 10).monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                    Text("到期：\(item.usage?.expiryLabel ?? "未提供期限")")
                        .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2)
                    if item.usage?.status == "stale" {
                        Label("历史数据", systemImage: "clock.arrow.circlepath")
                            .font(.system(size: 9, weight: .medium)).foregroundStyle(.orange)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
            }.buttonStyle(.plain).disabled(!canSelect)
                .help(item.name + "\n已用 / 总量；以服务商订阅返回值为准。")
                .accessibilityLabel(accessibilitySummary)
            Menu {
                Button("删除订阅", role: .destructive, action: onDelete).disabled(!canDelete)
                if connected { Text("停止连接后可删除当前订阅") }
            } label: { Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)) }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 20, height: 20)
                .help("管理「\(item.name)」").accessibilityLabel("管理订阅：\(item.name)")
        }.padding(12)
            .background(selected ? Color.blue.opacity(0.075) : (hovered ? Color.primary.opacity(0.035) : Color.clear), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(selected ? Color.blue.opacity(0.22) : Color.primary.opacity(0.065)))
            .onHover { hovered = $0 }
            .contextMenu {
                Button("删除订阅", role: .destructive, action: onDelete).disabled(!canDelete)
                if connected { Text("停止连接后可删除当前订阅") }
            }
    }
}

struct NodeSelectorControl: NSViewRepresentable {
    var names: [String]
    var titles: [String]
    @Binding var selection: String
    var enabled: Bool
    /// 仅在用户从菜单中选择时调用；刷新列表等程序性更新不会触发。
    var onChoose: (String) -> Void = { _ in }

    func makeCoordinator() -> Coordinator { Coordinator(selection: $selection, onChoose: onChoose) }

    func makeNSView(context: Context) -> NSPopUpButton {
        let control = NSPopUpButton(frame: .zero, pullsDown: false)
        control.isBordered = false
        control.isTransparent = true
        (control.cell as? NSPopUpButtonCell)?.arrowPosition = .noArrow
        control.focusRingType = .exterior
        control.autoenablesItems = false
        control.setContentHuggingPriority(.defaultLow, for: .horizontal)
        control.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        control.target = context.coordinator
        control.action = #selector(Coordinator.choose(_:))
        return control
    }

    func updateNSView(_ control: NSPopUpButton, context: Context) {
        context.coordinator.selection = $selection
        context.coordinator.onChoose = onChoose
        if control.itemTitles != titles {
            control.removeAllItems()
            control.addItems(withTitles: titles)
        }
        for (index, name) in names.enumerated() { control.item(at: index)?.representedObject = name }
        if let index = names.firstIndex(of: selection) { control.selectItem(at: index) }
        else { control.select(nil) }
        control.isEnabled = enabled
        control.toolTip = selection.isEmpty ? "先选择机场订阅，再选择中转节点" : selection
        control.setAccessibilityLabel("选择中转节点")
        control.setAccessibilityValue(control.titleOfSelectedItem ?? "尚未选择")
    }

    final class Coordinator: NSObject {
        var selection: Binding<String>
        var onChoose: (String) -> Void
        init(selection: Binding<String>, onChoose: @escaping (String) -> Void) { self.selection = selection; self.onChoose = onChoose }
        @objc func choose(_ sender: NSPopUpButton) {
            guard let value = sender.selectedItem?.representedObject as? String else { return }
            selection.wrappedValue = value
            onChoose(value)
        }
    }
}

struct ContentView: View {
    @ObservedObject var model: Model
    @Environment(\.scenePhase) private var scenePhase
    @State private var search = ""
    @State private var adding = false
    @State private var editing: ExitProfile?
    @State private var deleting = false
    @State private var confirming = false
    @State private var restoring = false
    @State private var addingSubscription = false
    @State private var subscriptionToDelete: Subscription?
    @State private var migrating = false
    @State private var targetSubscription: Subscription?
    @State private var nodeSelectorHovered = false

    private var filtered: [ExitProfile] {
        model.profiles.filter { search.isEmpty || "\($0.name) \($0.server)".localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 234)
            Divider()
            VStack(spacing: 16) {
                header
                if !model.serviceReady { serviceNotice }
                if model.recoveryNeeded || !model.serviceError.isEmpty { recoveryNotice }
                exitCard
                library
                connectionBar
            }.padding(22).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .safeAreaInset(edge: .bottom, spacing: 0) { statusBar }
        .frame(minWidth: 960, minHeight: 720)
        .task { model.load() }
        .onChange(of: scenePhase) { _, phase in if phase == .active { model.refreshServiceStatus() } }
        .onChange(of: search) { _, _ in reconcileSelection() }
        .onChange(of: model.prewarmKey) { _, _ in model.prewarm() }
        .onChange(of: model.profiles.map { "\($0.id) \($0.name) \($0.server)" }) { _, _ in reconcileSelection() }
        .sheet(isPresented: $adding) { AddView(model: model) }
        .sheet(item: $editing) { profile in AddView(model: model, existing: profile) }
        .sheet(isPresented: $addingSubscription) { AddSubscriptionView(model: model) }
        .alert("删除所选静态 IP？", isPresented: $deleting) {
            Button("取消", role: .cancel) {}
            Button("删除", role: .destructive) {
                if let id = model.selected { model.call(["op": "delete", "id": id]) }
            }
        } message: { Text("删除本机记录和钥匙串密码。删除后，需重新添加才能再次选择这个出口。") }
        .alert(model.running ? "应用这个静态出口？" : "保存这个出口选择？", isPresented: $confirming) {
            Button("取消", role: .cancel) {}
            Button(model.running ? "验证并切换" : "保存选择") {
                if let id = model.selected { model.call(["op": "switch", "id": id, "relay": model.relay]) }
            }
        } message: {
            Text("\(model.selectedProfile?.server ?? "") · \(model.relay)\n" + (model.running ? "先备份并验证出口，失败恢复原配置。" : "保存静态 IP 和中转节点，点击开始连接后生效。"))
        }
        .alert("恢复上次配置？", isPresented: $restoring) {
            Button("取消", role: .cancel) {}
            Button("恢复") { model.call(["op": "restore"]) }
        } message: { Text("恢复上一次切换前的配置和出口。") }
        .alert("切换机场订阅？", isPresented: Binding(get: { targetSubscription != nil }, set: { if !$0 { targetSubscription = nil } }), presenting: targetSubscription) { item in
            Button("取消", role: .cancel) { targetSubscription = nil }
            Button("切换") { selectSubscription(item); targetSubscription = nil }
        } message: { item in Text("切换到「\(item.name)」，保留静态出口和国内直连规则。切换过程中可能短暂影响新建连接。") }
        .alert("删除订阅？", isPresented: Binding(get: { subscriptionToDelete != nil }, set: { if !$0 { subscriptionToDelete = nil } }), presenting: subscriptionToDelete) { item in
            Button("取消", role: .cancel) { subscriptionToDelete = nil }
            Button("删除", role: .destructive) {
                model.call(["op": "delete_subscription", "uid": item.uid]) { ok in if ok { model.load(verify: false) } }
                subscriptionToDelete = nil
            }.disabled(!canDeleteSubscription(item))
        } message: { item in Text("删除本机保存的「\(item.name)」及其节点，不会取消服务商套餐。") }
        .alert("从 Clash Verge 迁移配置？", isPresented: $migrating) {
            Button("取消", role: .cancel) {}
            Button("迁移到独立版") { model.call(["op": "migrate"]) { ok in if ok { model.load(verify: false) } } }
        } message: { Text("一次性复制本机订阅和静态 IP。迁移后由独立版保存和管理，日常运行无需 Clash Verge。") }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "network").font(.system(size: 22, weight: .medium)).foregroundStyle(.blue)
                    .frame(width: 38, height: 38)
                    .background(Color.blue.opacity(0.09), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 4) {
                    Text("静态出口").font(.system(size: 15, weight: .semibold))
                    Text("个人网络管理").font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 16).padding(.top, 22).padding(.bottom, 24)
            HStack(spacing: 6) {
                Text("机场订阅").font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                Text("\(model.subscriptions.count)")
                    .font(.system(size: 10, weight: .medium).monospacedDigit()).foregroundStyle(.secondary)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Color.primary.opacity(0.05), in: Capsule())
                Spacer()
                Menu {
                    Button("添加订阅链接") { addingSubscription = true }
                    Button("导入本地 YAML") { importSubscription() }
                } label: { Image(systemName: "plus").font(.system(size: 13, weight: .medium)) }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 24, height: 24)
                    .help("添加机场订阅").accessibilityLabel("添加机场订阅").disabled(model.busy)
            }.padding(.horizontal, 16).padding(.bottom, 10)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    VStack(spacing: 8) {
                        ForEach(model.subscriptions) { item in
                            SubscriptionRow(item: item, selected: item.uid == model.subscriptionUID,
                                            canSelect: !model.busy && model.stateKnown && !model.recoveryNeeded,
                                            canDelete: canDeleteSubscription(item),
                                            connected: model.running && item.uid == model.subscriptionUID,
                                            onSelect: {
                                if item.uid != model.subscriptionUID {
                                    if model.running { targetSubscription = item } else { selectSubscription(item) }
                                }
                            }, onDelete: { subscriptionToDelete = item })
                        }
                    }
                    if model.subscriptions.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "server.rack").font(.system(size: 24)).foregroundStyle(.secondary)
                            Text("还没有机场订阅").font(.callout)
                            Button("添加订阅") { addingSubscription = true }
                            Button("导入 YAML") { importSubscription() }.buttonStyle(.link)
                        }.frame(maxWidth: .infinity).padding(.vertical, 20).disabled(model.busy)
                    }
                    if !model.subscriptionUID.isEmpty { subscriptionUsageCard }
                    if !model.migrated && model.subscriptions.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("已有 Clash Verge 配置？").font(.caption.weight(.medium))
                            Text("首次使用可复制订阅与静态 IP，之后独立管理。").font(.system(size: 11)).foregroundStyle(.secondary)
                            Button("迁移已有配置") { migrating = true }.controlSize(.small).disabled(model.busy)
                        }.padding(12).background(Color.blue.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
                    }
                }.padding(.horizontal, 12).padding(.bottom, 16)
            }
            Divider().padding(.horizontal, 16)
            Button { restoring = true } label: {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.uturn.backward")
                    Text("恢复上次配置")
                    Spacer()
                }.font(.system(size: 11)).padding(12).contentShape(Rectangle())
            }.buttonStyle(.plain).disabled(model.busy || !model.hasBackup)
                .padding(.horizontal, 4).padding(.vertical, 8)
        }.frame(maxHeight: .infinity).background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
    }

    private var subscriptionUsageCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 6) {
                Text("当前套餐").font(.system(size: 11, weight: .semibold))
                if model.currentUsage?.status == "stale" {
                    Text("历史数据").font(.system(size: 9, weight: .medium)).foregroundStyle(.orange)
                }
                Spacer(minLength: 3)
                Button { model.refreshSubscriptionUsage() } label: {
                    Image(systemName: "arrow.clockwise").font(.system(size: 12))
                        .frame(width: 24, height: 24).contentShape(Rectangle())
                }.buttonStyle(.borderless).disabled(model.busy)
                    .help("刷新用量").accessibilityLabel("刷新用量")
            }
            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("已用流量").font(.system(size: 10)).foregroundStyle(.secondary)
                    Text(model.currentUsage?.usedLabel ?? "未提供")
                        .font(.system(size: 16, weight: .semibold).monospacedDigit()).lineLimit(1).minimumScaleFactor(0.8)
                }
                Spacer(minLength: 0)
                VStack(alignment: .trailing, spacing: 6) {
                    Text("套餐总量").font(.system(size: 10)).foregroundStyle(.secondary)
                    Text(model.currentUsage?.totalLabel ?? "未提供")
                        .font(.system(size: 14, weight: .medium).monospacedDigit()).lineLimit(1).minimumScaleFactor(0.8)
                }
            }
            if let value = model.currentUsage?.fraction {
                GeometryReader { geometry in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.primary.opacity(0.07))
                        Capsule().fill(value >= 0.9 ? Color.orange : Color.blue)
                            .frame(width: geometry.size.width * value)
                    }
                }.frame(height: 4)
                    .accessibilityLabel("套餐用量比例")
                    .accessibilityValue("\(Int(value * 100))%")
            }
            HStack(alignment: .top, spacing: 6) {
                Image(systemName: "calendar").foregroundStyle(.secondary)
                Text("到期").foregroundStyle(.secondary)
                Spacer(minLength: 2)
                Text(model.currentUsage?.expiryLabel ?? "未提供期限")
                    .multilineTextAlignment(.trailing).fixedSize(horizontal: false, vertical: true)
                    .help(model.currentUsage?.fullExpiryLabel ?? "服务商未提供期限")
            }.font(.system(size: 10))
            Text(model.currentUsage?.snapshotLabel ?? "尚无用量数据")
                .font(.system(size: 9)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let reason = model.currentUsage?.reason, !reason.isEmpty {
                Text(reason).font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if !model.usageMessage.isEmpty {
                Text(model.usageMessage).font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            Button {
                model.call(["op": "update_subscription", "uid": model.subscriptionUID]) { ok in if ok { model.load(verify: false) } }
            } label: {
                Label("更新节点", systemImage: "arrow.triangle.2.circlepath").frame(maxWidth: .infinity)
            }.buttonStyle(ConnectionButtonStyle()).disabled(model.busy)
        }.padding(14)
            .background(Color(nsColor: .windowBackgroundColor).opacity(0.55), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.08)))
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("连接概览").font(.system(size: 22, weight: .bold))
                Text("国内直连 · 国外 TCP 使用静态出口").font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
            Button { model.load() } label: { Label("刷新", systemImage: "arrow.clockwise") }.disabled(model.busy)
            if model.serviceReady {
                Menu {
                    Button("重新安装网络服务") { model.registerService() }.disabled(model.running || !model.stateKnown || model.busy)
                } label: { Image(systemName: "gearshape") }.menuStyle(.borderlessButton).fixedSize()
                    .help(model.running ? "停止连接后可重新安装网络服务" : "网络服务")
            }
        }
    }

    private var serviceNotice: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "lock.shield").font(.title2).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text(model.serviceLabel).font(.system(size: 12, weight: .semibold))
                Text("安装时需要输入一次管理员密码；订阅和静态 IP 可以先离线管理。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 5)
            Button("安装网络服务") { model.registerService() }.disabled(model.busy)
        }.padding(14).background(Color.orange.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
    }

    private var recoveryNotice: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.shield").font(.title2).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 5) {
                Text(model.recoveryNeeded ? "上次配置操作尚未恢复完成" : "网络服务状态需要确认")
                    .font(.system(size: 12, weight: .semibold))
                if !model.serviceError.isEmpty { Text(model.serviceError).font(.system(size: 11)).textSelection(.enabled) }
                Text(model.recoveryNeeded ? "请先停止连接，确认服务停止后再选择出口或恢复配置。" : "未确认服务停止前，暂停切换订阅和启动新连接；你仍可尝试停止连接。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 5)
            Button("停止连接") { model.call(["op": "stop"]) { ok in if ok { model.load(verify: false) } } }.disabled(model.busy)
        }.padding(14).background(Color.orange.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
    }

    private var exitCard: some View {
        HStack(alignment: .center, spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 14).fill(Color.blue.opacity(0.09)).frame(width: 52, height: 52)
                Image(systemName: "globe").font(.system(size: 26, weight: .light)).foregroundStyle(.blue)
            }
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Text("当前公网出口").font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
                    if model.checking { ProgressView().controlSize(.mini) }
                }
                HStack(spacing: 10) {
                    Text(model.exitIP.isEmpty ? (!model.stateKnown ? "状态待确认" : (model.running ? "等待检测" : "尚未连接")) : model.exitIP)
                        .font(.system(size: model.exitIP.isEmpty ? 23 : 29, weight: .semibold, design: .monospaced))
                        .textSelection(.enabled).lineLimit(1).minimumScaleFactor(0.8)
                    if !model.exitIP.isEmpty {
                        Button { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(model.exitIP, forType: .string) } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless).help("复制出口 IP").accessibilityLabel("复制出口 IP")
                    }
                }
                if !model.exitIP.isEmpty {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: "mappin.and.ellipse").foregroundStyle(.blue.opacity(0.8))
                        Text(model.loadingExitLocation ? "正在查询地点…" : (model.exitLocation?.label ?? "地点暂不可用"))
                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        if model.exitLocation?.status == "stale" {
                            Text("历史缓存").font(.system(size: 10)).foregroundStyle(.tertiary)
                        }
                    }
                    .font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
                    .help(model.exitLocation?.help ?? "连接验证后单独查询 IP 归属地，查询失败不影响网络连接。")
                }
                if let at = model.verifiedAt {
                    Text("已实测 · \(at.formatted(date: .omitted, time: .standard))").font(.caption).foregroundStyle(.secondary)
                } else {
                    Text(model.checking ? "正在通过当前线路检测…" : (!model.stateKnown ? "无法确认连接状态，请刷新或停止连接" : (model.running ? "检测后显示实际公网出口" : "选择订阅与静态 IP，然后开始连接")))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            VStack(alignment: .trailing, spacing: 10) {
                Pill(title: !model.stateKnown ? "状态未知" : (model.connectionVerified ? "已验证连接" : (model.running ? "待验证" : "未连接")), symbol: !model.stateKnown ? "exclamationmark.triangle" : (model.connectionVerified ? "checkmark.shield" : "pause.circle"), color: model.connectionVerified ? .green : (model.running || !model.stateKnown ? .orange : .secondary))
                if model.running && model.stateKnown {
                    Button("重新检测") { model.call(["op": "verify"]) }.controlSize(.small).disabled(model.busy)
                }
            }
        }.padding(20).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.primary.opacity(0.07)))
    }

    private var library: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("静态 IP 库").font(.headline)
                Text("\(model.profiles.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                Spacer()
                Button { importCSV() } label: { Label("导入 CSV", systemImage: "square.and.arrow.down") }
                Button { adding = true } label: { Label("添加", systemImage: "plus") }
            }.disabled(model.busy).padding(14)
            Divider()
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("搜索名称或 IP 地址", text: $search).textFieldStyle(.plain)
                if !search.isEmpty {
                    Button { search = "" } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.plain).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 14).padding(.vertical, 10)
            Divider()
            if model.profiles.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "externaldrive.badge.plus").font(.system(size: 28, weight: .light)).foregroundStyle(.secondary)
                    Text("还没有保存的静态 IP").font(.headline)
                    Text("导入服务商 CSV，或添加代理地址和账号。").font(.caption).foregroundStyle(.secondary)
                    Button("导入 CSV") { importCSV() }.disabled(model.busy)
                }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(20)
            } else {
                Table(filtered, selection: Binding(get: { model.selected }, set: { value in
                    model.selected = value
                    model.chooseProfile(value)
                })) {
                    TableColumn("名称") { profile in
                        HStack(spacing: 7) {
                            Image(systemName: "externaldrive").foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(profile.name).fontWeight(.medium)
                                if profile.server == model.configuredServer && profile.port == model.configuredPort {
                                    Text(model.running ? "当前出口" : "已保存选择").font(.system(size: 10, weight: .medium)).foregroundStyle(.blue)
                                }
                            }
                        }.help(profile.name)
                    }.width(min: 105, ideal: 145)
                    TableColumn("代理地址") { profile in Text(profile.address).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) }.width(min: 155, ideal: 170)
                    TableColumn("协议") { profile in Text(profile.protocol.uppercased()).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary) }.width(65)
                    TableColumn("到期时间") { profile in Text(profile.expiryLabel).font(.system(size: 11)).foregroundStyle(.secondary) }.width(min: 78, ideal: 88)
                }.tableStyle(.inset).alternatingRowBackgrounds(.disabled)
                    .overlay {
                        if filtered.isEmpty {
                            VStack(spacing: 7) {
                                Image(systemName: "magnifyingglass").font(.title2)
                                Text("没有匹配的静态 IP").font(.callout)
                                Text("试试其他名称或地址").font(.caption)
                            }.foregroundStyle(.secondary).allowsHitTesting(false)
                        }
                    }
                    .contextMenu {
                        Button("编辑") { editing = model.selectedProfile }.disabled(model.selected == nil)
                        Button("删除", role: .destructive) { deleting = true }.disabled(model.selected == nil)
                    }.disabled(model.busy)
            }
            Divider()
            HStack {
                Text(model.selectedProfile.map { "已选：\($0.name)" } ?? "选择一条静态 IP").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Spacer()
                Button("编辑") { editing = model.selectedProfile }
                Button("删除") { deleting = true }
            }.controlSize(.small).disabled(model.selected == nil || model.busy).padding(.horizontal, 14).padding(.vertical, 9)
        }.frame(minHeight: 220, maxHeight: .infinity)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.08)))
    }

    private var connectionBar: some View {
        VStack(spacing: 12) {
            nodeSelector
            HStack(spacing: 8) {
                if !model.latencyProgress.isEmpty {
                    ProgressView().controlSize(.mini)
                    Text(model.latencyProgress).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    Button("取消测速") { model.cancelLatencyTest() }
                        .buttonStyle(ConnectionButtonStyle())
                } else {
                    HStack(spacing: 8) {
                        Button { model.testNodeLatencies(onlySelected: true) } label: {
                            Label("测当前节点", systemImage: "speedometer")
                        }
                        Button { model.testNodeLatencies() } label: {
                            Label("立即刷新", systemImage: "arrow.clockwise")
                        }.help("立即测速全部节点；应用打开期间每 10 分钟也会自动测速。")
                    }.buttonStyle(ConnectionButtonStyle())
                        .disabled(model.busy || model.subscriptionUID.isEmpty || model.nodes.isEmpty || !model.stateKnown || model.recoveryNeeded)
                }
                Spacer(minLength: 12)
                HStack(spacing: 8) {
                    Button(model.running ? "应用所选出口" : "保存选择") { confirming = true }
                        .buttonStyle(ConnectionButtonStyle())
                        .disabled(model.selected == nil || model.relay.isEmpty || !model.stateKnown || model.recoveryNeeded)
                    if model.shouldOfferStop {
                        Button {
                            model.call(["op": "stop"]) { ok in if ok { model.load(verify: false) } }
                        } label: {
                            Label("停止连接", systemImage: "stop.fill").frame(minWidth: 80)
                        }.buttonStyle(ConnectionButtonStyle(prominent: true, tint: .orange))
                    } else {
                        Button {
                            if let id = model.selected { model.call(["op": "start", "id": id, "relay": model.relay]) }
                        } label: {
                            Label("开始连接", systemImage: "power").frame(minWidth: 80)
                        }.buttonStyle(ConnectionButtonStyle(prominent: true))
                            .disabled(model.selected == nil || model.relay.isEmpty || model.subscriptionUID.isEmpty || !model.serviceReady || !model.stateKnown || model.recoveryNeeded)
                    }
                }.disabled(model.busy)
            }
        }.padding(14)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.08)))
    }

    private var nodeSelector: some View {
        ZStack {
            HStack(spacing: 12) {
                Image(systemName: "server.rack")
                    .font(.system(size: 17)).foregroundStyle(.blue)
                    .frame(width: 34, height: 34)
                    .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 4) {
                    Text("中转节点").font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
                    Text(model.relay.isEmpty ? "请选择订阅和节点" : model.relay)
                        .font(.system(size: 13, weight: .medium)).foregroundStyle(.primary)
                        .lineLimit(1).truncationMode(.tail)
                }
                Spacer(minLength: 12)
                if !model.relay.isEmpty {
                    Label(model.nodeDelayLabel(model.relay), systemImage: "waveform.path.ecg")
                        .help(model.nodeDelayHelp(model.relay))
                        .font(.system(size: 11, weight: .medium).monospacedDigit())
                        .foregroundStyle(.secondary).padding(.horizontal, 9).padding(.vertical, 6)
                        .background(Color.primary.opacity(0.045), in: Capsule()).fixedSize()
                }
                Image(systemName: "chevron.down").font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
            }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .windowBackgroundColor).opacity(0.55), in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(nodeSelectorHovered && !model.busy ? Color.blue.opacity(0.55) : Color.primary.opacity(0.10)))
                .contentShape(RoundedRectangle(cornerRadius: 10))
                .accessibilityHidden(true)
            NodeSelectorControl(names: model.nodes,
                                titles: model.nodes.map { "\($0)  ·  \(model.nodeDelayLabel($0))" },
                                selection: $model.relay,
                                enabled: !model.busy && !model.nodes.isEmpty,
                                onChoose: { model.chooseRelay($0) })
        }.frame(height: 58)
            .onHover { nodeSelectorHovered = $0 }
            .opacity(model.busy || model.nodes.isEmpty ? 0.5 : 1)
    }

    private var statusBar: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                if model.busy { ProgressView().controlSize(.mini) }
                else { Image(systemName: model.error ? "exclamationmark.circle" : "checkmark.circle").foregroundStyle(model.error ? Color.orange : .secondary) }
                Text(model.busy ? model.activity : (model.message.isEmpty ? "就绪 · 订阅与静态 IP 保存在本机" : model.message))
                    .font(.system(size: 12)).textSelection(.enabled).lineLimit(3)
                Spacer(minLength: 8)
                Text("独立版 v0.3.12").font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
            }.padding(.horizontal, 18).padding(.vertical, 10).frame(minHeight: 39).background(Color(nsColor: .controlBackgroundColor))
        }
    }

    private func selectSubscription(_ item: Subscription) {
        model.call(["op": "select_subscription", "uid": item.uid])
    }

    private func canDeleteSubscription(_ item: Subscription) -> Bool {
        !model.busy && model.stateKnown && !model.recoveryNeeded &&
        model.subscriptions.contains { $0.uid == item.uid } &&
        !(model.running && item.uid == model.subscriptionUID)
    }

    private func reconcileSelection() {
        if let id = model.selected, !filtered.contains(where: { $0.id == id }) { model.selected = nil }
    }

    private func importCSV() {
        let panel = NSOpenPanel()
        panel.title = "导入静态 IP CSV"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { model.call(["op": "import", "path": url.path]) }
    }

    private func importSubscription() {
        let panel = NSOpenPanel()
        panel.title = "导入机场订阅 YAML"
        panel.message = "选择包含代理节点的 YAML 配置。导入后可在本机独立管理。"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            model.call(["op": "import_subscription", "path": url.path, "name": url.deletingPathExtension().lastPathComponent]) { ok in
                if ok { model.load(verify: false) }
            }
        }
    }
}

struct AddSubscriptionView: View {
    @ObservedObject var model: Model
    @Environment(\.dismiss) private var dismiss
    @State private var url = ""
    private var validURL: Bool {
        guard let value = URL(string: url.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = value.scheme?.lowercased(), ["https", "http"].contains(scheme),
              let host = value.host, !host.isEmpty else { return false }
        return true
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("添加机场订阅").font(.title2.bold())
            Text("粘贴订阅链接，名称将自动获取。").font(.callout).foregroundStyle(.secondary)
            Form {
                SecureField("订阅链接", text: $url)
            }.textFieldStyle(.roundedBorder)
            Text("订阅链接可能包含访问凭证，只在本机保存。添加后可随时更新节点。").font(.caption).foregroundStyle(.secondary)
            if model.error { Text(model.message).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                Button("添加订阅") {
                    model.call(["op": "add_subscription", "url": url.trimmingCharacters(in: .whitespacesAndNewlines)]) { ok in
                        if ok { dismiss(); model.load(verify: false) }
                    }
                }.buttonStyle(.borderedProminent).disabled(!validURL)
            }.disabled(model.busy)
        }.padding(24).frame(width: 460)
    }
}

struct AddView: View {
    @ObservedObject var model: Model
    var existing: ExitProfile? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var server = ""
    @State private var port = "443"
    @State private var username = ""
    @State private var password = ""
    @State private var expected = ""
    @State private var proto = "socks5"
    @State private var expired = ""
    private var validPort: Bool { Int(port).map { (1...65535).contains($0) } ?? false }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(existing == nil ? "添加静态 IP" : "编辑静态 IP").font(.title2.bold())
            Form {
                Section("代理信息") {
                    TextField("名称", text: $name)
                    TextField("服务器地址", text: $server)
                    TextField("端口", text: $port)
                    Picker("协议", selection: $proto) {
                        Text("SOCKS5").tag("socks5")
                        Text("HTTP").tag("http")
                        Text("HTTPS").tag("https")
                    }
                }
                Section("认证与校验") {
                    TextField("账号", text: $username)
                    SecureField(existing == nil ? "密码" : "密码（留空保留）", text: $password)
                    TextField("预期出口 IP", text: $expected)
                    TextField("到期时间", text: $expired)
                }
            }.formStyle(.grouped)
            Text("密码保存在钥匙串。预期 IP 留空时，只检查公网连通性。").font(.caption).foregroundStyle(.secondary)
            if model.error { Text(model.message).font(.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                Button("保存") {
                    model.call(["op": "save", "profile": ["id": existing?.id ?? "", "name": name, "server": server, "port": port, "protocol": proto, "username": username, "password": password, "expected": expected, "expired": expired]]) { ok in if ok { dismiss() } }
                }.buttonStyle(.borderedProminent).disabled(server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !validPort)
            }.disabled(model.busy)
        }.padding(22).frame(width: 450, height: 550)
            .onAppear {
                if let profile = existing {
                    name = profile.name; server = profile.server; port = String(profile.port)
                    username = profile.username; expected = profile.expected; proto = profile.protocol; expired = profile.expired
                }
            }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// 用户已在系统设置放行本应用；清除包内其余文件的下载隔离标记，避免内置 Python 和内核再被逐个拦截。
    /// 隔离标记不属于签名内容；应用位于只读位置时静默失败。
    func applicationDidFinishLaunching(_ notification: Notification) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
        task.arguments = ["-dr", "com.apple.quarantine", Bundle.main.bundlePath]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        // 同步等待（通常几十毫秒），确保首次启动后台前已清除。
        if (try? task.run()) != nil { task.waitUntilExit() }
    }
}

struct ManagerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = Model()
    var body: some Scene {
        Window("静态出口管理器 · 独立版", id: "main") { ContentView(model: model) }
            .defaultSize(width: 1100, height: 820)
            .windowResizability(.contentMinSize)
            .commands {
                CommandGroup(replacing: .appTermination) {
                    Button("停止连接并退出") {
                        model.call(["op": "stop"]) { ok in
                            if ok && model.stateKnown && !model.running { NSApplication.shared.terminate(nil) }
                            else if ok { model.error = true; model.message = "尚未确认连接已经停止，管理器保持打开。请刷新后再试。" }
                        }
                    }.disabled(model.busy)
                    Button(model.shouldOfferStop ? "退出管理器（不停止连接）" : "退出管理器") { NSApplication.shared.terminate(nil) }
                        .keyboardShortcut("q").disabled(model.busy)
                }
            }
    }
}

ManagerApp.main()
