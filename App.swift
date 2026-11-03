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

struct UpdateInfo: Decodable, Identifiable {
    let latest: String
    let notes: String
    let url: String
    let sha256: String
    let page: String
    var id: String { latest }
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
    @Published var update: UpdateInfo?
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
    /// 国内也走静态 IP：仅在使用静态 IP 时生效，公网 UDP 全部拒绝。
    @Published var globalStatic = false
    @Published var syncTimezone = false
    /// 直连白名单：命中的域名与 IP 不经静态 IP 和中转节点，三种模式下都生效。
    @Published var directWhitelist: [String] = []
    @Published var browserLanguage = false
    /// 网络服务当前套用的出口时区；空表示系统时区未被修改。
    @Published var appliedTimezone = ""
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
        guard running, stateKnown, !recoveryNeeded, !busy, name != activeRelay else { return }
        call(["op": "switch", "id": selected ?? "", "relay": name])
    }

    /// 已连接时在静态 IP 列表中改选另一条，即沿用当前中转切换到该静态出口；取消选择则改为仅用中转节点出口。
    /// 失败自动恢复原出口。未连接时只改变选择，仍由用户点「开始连接」。
    func chooseProfile(_ id: String?) {
        let target = id ?? ""
        guard running, stateKnown, !recoveryNeeded, !busy, target != activeProfileID,
              target.isEmpty || profiles.contains(where: { $0.id == target }) else { return }
        let currentRelay = activeRelay.isEmpty ? relay : activeRelay
        guard !currentRelay.isEmpty else { return }
        call(["op": "switch", "id": target, "relay": currentRelay])
    }

    /// 已连接时立即按当前出口重新应用并验证，失败自动恢复；未连接时只记住设置。
    func setGlobalStatic(_ enabled: Bool) {
        guard enabled != globalStatic, stateKnown, !recoveryNeeded, !busy else { return }
        let profileID = running ? activeProfileID : (selected ?? "")
        let currentRelay = running && !activeRelay.isEmpty ? activeRelay : relay
        call(["op": "set_global_static", "enabled": enabled, "id": profileID, "relay": currentRelay])
    }

    /// 已连接时立即按当前出口重新应用并验证，失败自动恢复原白名单；未连接时只保存。
    func setWhitelist(_ entries: [String], completion: @escaping (Bool) -> Void) {
        guard stateKnown, !recoveryNeeded, !busy else { completion(false); return }
        let profileID = running ? activeProfileID : (selected ?? "")
        let currentRelay = running && !activeRelay.isEmpty ? activeRelay : relay
        call(["op": "set_whitelist", "entries": entries, "id": profileID, "relay": currentRelay], completion: completion)
    }

    /// 系统时区跟随出口：已连接时立即设置或恢复，刷新网页即可生效；未连接时只记住设置。
    /// Chrome 网页与界面语言改为 en-US 或还原；Chrome 运行中会被正常退出、修改后恢复会话重开。
    func setBrowserLanguage(_ enabled: Bool) {
        guard enabled != browserLanguage, !busy else { return }
        call(["op": "set_browser_language", "enabled": enabled])
    }

    func setSyncTimezone(_ enabled: Bool) {
        guard enabled != syncTimezone, stateKnown, !recoveryNeeded, !busy else { return }
        call(["op": "set_sync_timezone", "enabled": enabled, "ip": exitIP])
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

    /// 启动时（后端限制为每 24 小时一次）或手动检查 GitHub 最新 Release；发现新版本时弹窗。
    func checkForUpdates(manual: Bool) {
        Task {
            let reply = await backendReply(["op": "check_update", "force": manual])
            if reply["ok"] as? Bool == true, reply["available"] as? Bool == true, let info: UpdateInfo = decode(reply) {
                update = info
            } else if manual && !busy {
                error = reply["ok"] as? Bool != true
                message = error ? reply["error"] as? String ?? "检查更新失败。"
                    : "已是最新版本 v\(reply["current"] as? String ?? "")。"
            }
        }
    }

    /// 停止连接、下载并校验 dmg，再交给 update.sh 在应用退出后替换并重新打开。
    func installUpdate(_ info: UpdateInfo) {
        guard !busy else { return }
        let bundle = Bundle.main.bundleURL
        guard FileManager.default.isWritableFile(atPath: bundle.deletingLastPathComponent().path),
              let script = Bundle.main.resourceURL?.appendingPathComponent("update.sh") else {
            if let page = URL(string: info.page) { NSWorkspace.shared.open(page) }
            message = "当前位置没有写入权限，已打开下载页，请手动安装新版本。"
            return
        }
        busy = true
        error = false
        Task {
            if running || !stateKnown {
                message = "正在停止连接…"
                let stopped = await backendReply(["op": "stop"])
                guard stopped["ok"] as? Bool == true, stopped["running"] as? Bool != true else {
                    busy = false; error = true
                    message = stopped["error"] as? String ?? "无法停止连接，已取消更新。"
                    return
                }
            }
            message = "正在下载 v\(info.latest)…"
            let reply = await backendReply(["op": "download_update", "url": info.url, "sha256": info.sha256, "version": info.latest])
            guard reply["ok"] as? Bool == true, let dmg = reply["path"] as? String else {
                busy = false; error = true
                message = reply["error"] as? String ?? "下载更新失败。"
                return
            }
            // 替换期间旧应用包会被移走，先把脚本复制到临时目录再运行。
            let runner = FileManager.default.temporaryDirectory.appendingPathComponent("static-exit-update-\(UUID().uuidString).sh")
            do {
                try FileManager.default.copyItem(at: script, to: runner)
                let task = Process()
                task.executableURL = URL(fileURLWithPath: "/bin/sh")
                task.arguments = [runner.path, String(ProcessInfo.processInfo.processIdentifier), dmg, bundle.path]
                task.standardOutput = FileHandle.nullDevice
                task.standardError = FileHandle.nullDevice
                try task.run()
            } catch {
                busy = false; self.error = true
                message = "无法启动更新程序。"
                return
            }
            message = "正在安装 v\(info.latest)，应用将自动重新打开…"
            NSApplication.shared.terminate(nil)
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
            "set_global_static": running ? "正在切换国内流量出口并验证…" : "正在保存设置…",
            "set_sync_timezone": running ? "正在设置系统时区…" : "正在保存设置…",
            "set_whitelist": running ? "正在更新直连白名单并验证…" : "正在保存直连白名单…",
            "set_browser_language": "正在退出 Chrome 并修改语言…",
            "verify": "正在验证静态出口、系统 DNS 与网页连接…", "import_current": "正在载入当前静态 IP…",
            "import": "正在导入静态 IP…", "save": "正在保存…", "restore": "正在恢复配置…",
            "delete": "正在删除记录…", "start": "正在启动网络连接并验证出口…",
            "stop": "正在停止网络连接…", "migrate": "正在迁移本机订阅和静态 IP…",
            "add_subscription": "正在下载订阅…", "import_subscription": "正在导入订阅…",
            "update_subscription": "正在更新订阅…", "delete_subscription": "正在删除订阅…"
        ]
        activity = labels[op] ?? "正在处理…"
        let clearsExit = ["verify", "start", "stop", "switch", "select_subscription", "restore"].contains(op) || (["set_global_static", "set_whitelist"].contains(op) && running)
        if clearsExit { clearExitVerification() }
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
                reverifyIfCleared(clearsExit && op != "verify")
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
            reverifyIfCleared(clearsExit && op != "verify")
        }
    }

    /// 操作前清空了出口检测，但结果没有带回新出口（未改动、失败后恢复等）且仍在连接时，重新实测一次，避免停在「等待检测」。
    private func reverifyIfCleared(_ cleared: Bool) {
        guard cleared, running, stateKnown, !recoveryNeeded, exitIP.isEmpty else { return }
        call(["op": "verify"])
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
        guard !running, stateKnown, !recoveryNeeded, !relay.isEmpty else { return }
        prewarmTask?.cancel()
        let request: [String: Any] = ["op": "prewarm", "id": selected ?? "", "relay": relay]
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
            if !profiles.contains(where: { $0.id == selected }) { selected = nil }
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
        if let value = result["global_static"] as? Bool { globalStatic = value }
        if let value = result["sync_timezone"] as? Bool { syncTimezone = value }
        if let value = result["direct_whitelist"] as? [String] { directWhitelist = value }
        if let value = result["browser_language"] as? Bool { browserLanguage = value }
        if let value = result["timezone"] as? String { appliedTimezone = value }
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
        if let value = result["selected_id"] as? String {
            selected = profiles.contains(where: { $0.id == value }) ? value : nil
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

private extension NSColor {
    convenience init(rgb: UInt32) {
        self.init(srgbRed: CGFloat((rgb >> 16) & 0xFF) / 255, green: CGFloat((rgb >> 8) & 0xFF) / 255,
                  blue: CGFloat(rgb & 0xFF) / 255, alpha: 1)
    }
}

/// 界面配色：浅色取自设计稿，深色为对应的暗色版本。
enum Palette {
    static func dynamic(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            NSColor(rgb: appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light)
        })
    }
    static let accent = dynamic(0x2563EB, 0x3B82F6)
    static let accentText = dynamic(0x1D4ED8, 0x93B4FB)
    static let accentSoft = dynamic(0xEEF3FE, 0x1E2A44)
    static let accentBorder = dynamic(0xC9D8FB, 0x34507F)
    static let selected = dynamic(0xF5F8FF, 0x1A2236)
    static let text = dynamic(0x111827, 0xF3F4F6)
    static let text2 = dynamic(0x4B5563, 0xA9AFBA)
    static let text3 = dynamic(0x5F6673, 0x949AA5)
    static let border = dynamic(0xE4E7EC, 0x33363D)
    static let divider = dynamic(0xEEF0F3, 0x2A2D33)
    static let surface = dynamic(0xFFFFFF, 0x1E1F23)
    static let sidebar = dynamic(0xF2F3F6, 0x18191C)
    static let subtle = dynamic(0xF7F8FA, 0x25262B)
    static let chip = dynamic(0xF2F4F7, 0x2C2E33)
    static let track = dynamic(0xCDD2DA, 0x4A4E57)
    static let idle = dynamic(0xC4CAD4, 0x555A64)
    static let success = dynamic(0x067647, 0x4ADE80)
    static let successSoft = dynamic(0xECFDF3, 0x14301F)
    static let successDot = dynamic(0x17B26A, 0x22C55E)
    static let warning = dynamic(0xB54708, 0xFDB022)
    static let warningSoft = dynamic(0xFFF4E5, 0x3A2A12)
    static let danger = dynamic(0xB42318, 0xF97066)
    static let dangerSoft = dynamic(0xFEF3F2, 0x3A1A18)
    static let dangerBorder = dynamic(0xFECDCA, 0x5A2A26)
}

enum ExpiryStatus { case ok, soon, expired, unknown }

extension ExitProfile {
    /// 到期日只取前 10 位 yyyy-MM-dd；未填写或无法解析时为 nil。
    var daysLeft: Int? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        guard let date = formatter.date(from: String(expired.prefix(10))) else { return nil }
        let calendar = Calendar.current
        return calendar.dateComponents([.day], from: calendar.startOfDay(for: Date()), to: calendar.startOfDay(for: date)).day
    }
    var expiryStatus: ExpiryStatus {
        guard let days = daysLeft else { return .unknown }
        return days < 0 ? .expired : (days <= 14 ? .soon : .ok)
    }
}

extension SubscriptionUsage {
    var daysLeft: Int? {
        guard let expires_at, expires_at > 0 else { return nil }
        let calendar = Calendar.current
        let date = Date(timeIntervalSince1970: Double(expires_at))
        return calendar.dateComponents([.day], from: calendar.startOfDay(for: Date()), to: calendar.startOfDay(for: date)).day
    }
    var updatedShortLabel: String {
        if status == "stale" { return "历史数据" }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = fetched_at.flatMap({ formatter.date(from: $0) ?? ISO8601DateFormatter().date(from: $0) }) else { return "尚无数据" }
        let output = DateFormatter()
        output.dateFormat = "MM-dd HH:mm"
        return output.string(from: date)
    }
}

/// 设计稿的按钮样式：主按钮蓝底、次按钮白底描边、浅蓝强调、浅红断开、无边框图标。
struct PanelButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, tinted, danger, ghost }
    var kind: Kind = .secondary
    var height: CGFloat = 36
    var radius: CGFloat = 10
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let large = kind == .primary || kind == .danger
        let foreground: Color, background: Color, stroke: Color
        switch kind {
        case .primary: (foreground, background, stroke) = (.white, Palette.accent, .clear)
        case .secondary: (foreground, background, stroke) = (Palette.text, Palette.surface, Palette.border)
        case .tinted: (foreground, background, stroke) = (Palette.accentText, Palette.accentSoft, .clear)
        case .danger: (foreground, background, stroke) = (Palette.danger, Palette.dangerSoft, Palette.dangerBorder)
        case .ghost: (foreground, background, stroke) = (Palette.text2, .clear, .clear)
        }
        return configuration.label
            .font(.system(size: large ? 14 : 12, weight: large || kind == .tinted ? .semibold : .medium))
            .padding(.horizontal, kind == .ghost ? 8 : (large ? 18 : 13)).frame(height: height)
            .foregroundStyle(foreground)
            .background(background, in: RoundedRectangle(cornerRadius: radius))
            .overlay(RoundedRectangle(cornerRadius: radius).strokeBorder(stroke))
            .overlay(RoundedRectangle(cornerRadius: radius).fill(Color.primary.opacity(configuration.isPressed ? 0.08 : 0)))
            .shadow(color: kind == .primary && isEnabled ? Palette.accent.opacity(0.28) : .clear, radius: 8, y: 4)
            .opacity(isEnabled ? 1 : 0.45)
            .contentShape(RoundedRectangle(cornerRadius: radius))
    }
}

/// 整块可点的卡片、列表行：只加按下反馈和禁用透明度。
struct PressableStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(isEnabled ? (configuration.isPressed ? 0.8 : 1) : 0.55)
    }
}

struct PulseDot: View {
    var color: Color
    var animate: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var expanded = false
    var body: some View {
        Circle().fill(color).frame(width: 7, height: 7)
            .background(Circle().fill(color.opacity(expanded ? 0 : 0.45)).scaleEffect(expanded ? 2.8 : 1))
            .onAppear {
                guard animate && !reduceMotion else { return }
                withAnimation(.easeOut(duration: 2).repeatForever(autoreverses: false)) { expanded = true }
            }
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

    /// 头像配色按订阅 uid 固定，切换顺序不会变色。
    private var avatarColors: (Color, Color) {
        let options: [(Color, Color)] = [
            (Palette.dynamic(0xE3EBFD, 0x1E2A44), Palette.dynamic(0x1D4ED8, 0x93B4FB)),
            (Palette.dynamic(0xFDE9E2, 0x3A2018), Palette.dynamic(0xB93815, 0xF4A386)),
            (Palette.dynamic(0xE3F6EC, 0x14301F), Palette.dynamic(0x067647, 0x6EE7A0)),
            (Palette.dynamic(0xEFE8FD, 0x2A2140), Palette.dynamic(0x6D28D9, 0xC4B5FD))
        ]
        let sum = item.uid.unicodeScalars.reduce(0) { $0 + Int($1.value) }
        return options[sum % options.count]
    }

    var body: some View {
        HStack(spacing: 4) {
            Button(action: onSelect) {
                HStack(spacing: 10) {
                    Text(String(item.name.prefix(1))).font(.system(size: 14, weight: .semibold))
                        .frame(width: 32, height: 32)
                        .foregroundStyle(avatarColors.1)
                        .background(avatarColors.0, in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(item.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Palette.text).lineLimit(1)
                            if item.usage?.status == "stale" {
                                Text("历史数据").font(.system(size: 10, weight: .medium)).foregroundStyle(Palette.warning)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Palette.warningSoft, in: RoundedRectangle(cornerRadius: 5)).fixedSize()
                            }
                        }
                        Text("\(item.usage?.usedLabel ?? "未提供") / \(item.usage?.totalLabel ?? "未提供")")
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.text2).lineLimit(1)
                    }
                    Spacer(minLength: 0)
                    if selected {
                        Image(systemName: "checkmark").font(.system(size: 8, weight: .heavy)).foregroundStyle(.white)
                            .frame(width: 18, height: 18).background(Palette.accent, in: Circle())
                    }
                }.contentShape(Rectangle())
            }.buttonStyle(PressableStyle()).disabled(!canSelect)
                .help(item.name + "\n已用 / 总量；以服务商订阅返回值为准。")
                .accessibilityLabel(accessibilitySummary)
            if hovered {
                Menu {
                    Button("删除订阅", role: .destructive, action: onDelete).disabled(!canDelete)
                    if connected { Text("停止连接后可删除当前订阅") }
                } label: { Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)) }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 20, height: 20)
                    .help("管理「\(item.name)」").accessibilityLabel("管理订阅：\(item.name)")
            }
        }.padding(.horizontal, 10).padding(.vertical, 9)
            .background(selected ? Palette.surface : (hovered ? Color.primary.opacity(0.04) : Color.clear), in: RoundedRectangle(cornerRadius: 10))
            .shadow(color: selected ? .black.opacity(0.08) : .clear, radius: 2, y: 1)
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(selected ? Color.primary.opacity(0.06) : .clear))
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
    enum Filter: CaseIterable { case all, ok, soon, expired }
    enum SortKey { case name, expiry }

    @ObservedObject var model: Model
    @Environment(\.scenePhase) private var scenePhase
    @State private var search = ""
    @State private var filter: Filter = .all
    @State private var sortKey: SortKey = .expiry
    @State private var sortAscending = true
    @State private var adding = false
    @State private var editing: ExitProfile?
    @State private var profileToDelete: ExitProfile?
    @State private var purging = false
    @State private var confirming = false
    @State private var restoring = false
    @State private var addingSubscription = false
    @State private var subscriptionToDelete: Subscription?
    @State private var migrating = false
    @State private var targetSubscription: Subscription?
    @State private var nodeSelectorHovered = false
    @State private var languageTarget: Bool?
    @State private var editingWhitelist = false
    /// 关闭「使用静态 IP」前的选择，重新开启时优先恢复。
    @State private var lastProfileID: String?

    private var usingStatic: Bool { model.selected != nil }
    private var locked: Bool { model.busy || !model.stateKnown || model.recoveryNeeded }

    private func matches(_ profile: ExitProfile, _ filter: Filter) -> Bool {
        switch filter {
        case .all: return true
        case .ok: return [.ok, .unknown].contains(profile.expiryStatus)
        case .soon: return profile.expiryStatus == .soon
        case .expired: return profile.expiryStatus == .expired
        }
    }

    private var filtered: [ExitProfile] {
        model.profiles
            .filter { matches($0, filter) }
            .filter { search.isEmpty || "\($0.name) \($0.server)".localizedCaseInsensitiveContains(search) }
            .sorted { a, b in
                switch sortKey {
                case .name:
                    let order = a.name.localizedStandardCompare(b.name)
                    return sortAscending ? order == .orderedAscending : order == .orderedDescending
                case .expiry:
                    // 未填写到期时间的排在最后。
                    let left = a.daysLeft ?? Int.max, right = b.daysLeft ?? Int.max
                    return sortAscending ? left < right : left > right
                }
            }
    }

    private func isConfigured(_ profile: ExitProfile) -> Bool {
        profile.server == model.configuredServer && profile.port == model.configuredPort
    }

    /// 当前选择（静态 IP 与中转节点）是否与已保存配置一致。
    private var selectionSaved: Bool {
        let profileSaved = model.selectedProfile.map(isConfigured) ?? model.configuredServer.isEmpty
        return profileSaved && model.relay == model.activeRelay
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 248)
            Rectangle().fill(Palette.border).frame(width: 1)
            ScrollView {
                VStack(alignment: .leading, spacing: 26) {
                    header
                    if !model.serviceReady { serviceNotice }
                    if model.recoveryNeeded || !model.serviceError.isEmpty { recoveryNotice }
                    hero
                    exitSettings
                    library
                }.padding(.horizontal, 28).padding(.top, 24).padding(.bottom, 30)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
            }.background(Palette.surface)
        }
        .foregroundStyle(Palette.text)
        .frame(minWidth: 1000, minHeight: 720)
        .task { model.load(); model.checkForUpdates(manual: false) }
        .alert(item: $model.update) { info in
            Alert(title: Text("发现新版本 v\(info.latest)"),
                  message: Text(String(info.notes.prefix(600)) + "\n\n更新会先停止当前连接；完成后需在应用中重新安装一次网络服务。"),
                  primaryButton: .default(Text("立即更新")) { model.installUpdate(info) },
                  secondaryButton: .cancel(Text("稍后")))
        }
        .onChange(of: scenePhase) { _, phase in if phase == .active { model.refreshServiceStatus() } }
        .onChange(of: model.prewarmKey) { _, _ in model.prewarm() }
        .onChange(of: model.profiles.map { "\($0.id) \($0.name) \($0.server)" }) { _, _ in reconcileSelection() }
        .sheet(isPresented: $adding) { AddView(model: model) }
        .sheet(item: $editing) { profile in AddView(model: model, existing: profile) }
        .sheet(isPresented: $addingSubscription) { AddSubscriptionView(model: model) }
        .sheet(isPresented: $editingWhitelist) { WhitelistView(model: model) }
        .alert(model.running ? "应用这个静态出口？" : "保存这个出口选择？", isPresented: $confirming) {
            Button("取消", role: .cancel) {}
            Button(model.running ? "验证并切换" : "保存选择") {
                model.call(["op": "switch", "id": model.selected ?? "", "relay": model.relay])
            }
        } message: {
            Text("\(model.selectedProfile?.server ?? "不使用静态 IP") · \(model.relay)\n" + (model.running ? "先备份并验证出口，失败恢复原配置。" : "保存静态 IP 和中转节点，点击开始连接后生效。"))
        }
        .alert("恢复上次配置？", isPresented: $restoring) {
            Button("取消", role: .cancel) {}
            Button("恢复") { model.call(["op": "restore"]) }
        } message: { Text("恢复上一次切换前的配置和出口。") }
    }

    // MARK: - 侧栏

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "globe").font(.system(size: 17, weight: .medium)).foregroundStyle(.white)
                    .frame(width: 34, height: 34)
                    .background(Palette.accent, in: RoundedRectangle(cornerRadius: 9))
                    .shadow(color: Palette.accent.opacity(0.25), radius: 3, y: 2)
                VStack(alignment: .leading, spacing: 1) {
                    Text("静态出口").font(.system(size: 15, weight: .semibold))
                    Text("个人网络管理").font(.system(size: 11)).foregroundStyle(Palette.text2)
                }
            }.padding(.horizontal, 18).padding(.top, 20).padding(.bottom, 20)
            HStack(spacing: 6) {
                Text("机场订阅").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.text2)
                Spacer()
                Menu {
                    Button("添加订阅链接") { addingSubscription = true }
                    Button("导入本地 YAML") { importSubscription() }
                } label: { Image(systemName: "plus").font(.system(size: 13, weight: .medium)) }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 26, height: 26)
                    .help("添加机场订阅").accessibilityLabel("添加机场订阅").disabled(model.busy)
            }.padding(.leading, 20).padding(.trailing, 14).padding(.bottom, 4)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(spacing: 2) {
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
                            Image(systemName: "server.rack").font(.system(size: 24)).foregroundStyle(Palette.text3)
                            Text("还没有机场订阅").font(.callout)
                            Button("添加订阅") { addingSubscription = true }.buttonStyle(PanelButtonStyle(kind: .tinted))
                            Button("导入 YAML") { importSubscription() }.buttonStyle(.link)
                        }.frame(maxWidth: .infinity).padding(.vertical, 20).disabled(model.busy)
                    }
                    if !model.subscriptionUID.isEmpty { planCard }
                    if !model.migrated && model.subscriptions.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("已有 Clash Verge 配置？").font(.system(size: 12, weight: .semibold))
                            Text("首次使用可复制订阅与静态 IP，之后独立管理。").font(.system(size: 11)).foregroundStyle(Palette.text2)
                            Button("迁移已有配置") { migrating = true }.buttonStyle(PanelButtonStyle(kind: .secondary, height: 32)).disabled(model.busy)
                        }.padding(12).background(Palette.accentSoft, in: RoundedRectangle(cornerRadius: 12))
                    }
                }.padding(.horizontal, 12).padding(.vertical, 6)
            }
            sidebarFooter
        }.frame(maxHeight: .infinity).background(Palette.sidebar)
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

    private var planCard: some View {
        let usage = model.currentUsage
        return VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 6) {
                Text("当前套餐 · \(model.selectedSubscription?.name ?? "")").font(.system(size: 12, weight: .semibold)).lineLimit(1)
                Spacer(minLength: 4)
                Button { model.refreshSubscriptionUsage() } label: {
                    Image(systemName: "arrow.clockwise").font(.system(size: 12, weight: .medium)).frame(width: 28, height: 28).contentShape(Rectangle())
                }.buttonStyle(.plain).foregroundStyle(Palette.text2).disabled(model.busy)
                    .help("刷新用量").accessibilityLabel("刷新套餐用量")
            }
            HStack(spacing: 14) {
                ZStack {
                    Circle().stroke(Palette.divider, lineWidth: 7)
                    Circle().trim(from: 0, to: usage?.fraction ?? 0)
                        .stroke((usage?.fraction ?? 0) >= 0.9 ? Palette.warning : Palette.accent, style: StrokeStyle(lineWidth: 7, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                    Text(usage?.fraction.map { "\(Int(($0 * 100).rounded()))%" } ?? "—")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                }.frame(width: 60, height: 60)
                    .accessibilityElement(children: .ignore).accessibilityLabel("套餐用量比例")
                    .accessibilityValue(usage?.fraction.map { "\(Int($0 * 100))%" } ?? "未提供")
                VStack(alignment: .leading, spacing: 1) {
                    Text("已用流量").font(.system(size: 11)).foregroundStyle(Palette.text2)
                    Text(usage?.usedLabel ?? "未提供").font(.system(size: 17, weight: .semibold, design: .monospaced))
                        .lineLimit(1).minimumScaleFactor(0.7)
                    Text("共 \(usage?.totalLabel ?? "未提供")").font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.text2)
                        .lineLimit(1).minimumScaleFactor(0.8)
                }
            }
            VStack(spacing: 8) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("到期").foregroundStyle(Palette.text2)
                    Spacer(minLength: 4)
                    Text(usage?.expiryLabel ?? "未提供期限").font(.system(size: 11, design: .monospaced))
                        .help(usage?.fullExpiryLabel ?? "服务商未提供期限")
                    if let days = usage?.daysLeft, days >= 0 {
                        Text("· 剩 \(days) 天").fontWeight(.medium).foregroundStyle(Palette.success)
                    }
                }
                HStack(spacing: 6) {
                    Text("更新").foregroundStyle(Palette.text2)
                    Spacer(minLength: 4)
                    Text(usage?.updatedShortLabel ?? "尚无数据").font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(usage?.status == "stale" ? Palette.warning : Palette.text)
                        .help(usage?.snapshotLabel ?? "尚无用量数据")
                }
                ForEach([usage?.reason ?? "", model.usageMessage].filter { !$0.isEmpty }, id: \.self) { note in
                    Text(note).foregroundStyle(Palette.text2).frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }.font(.system(size: 11)).padding(.top, 12)
                .overlay(alignment: .top) { Rectangle().fill(Palette.divider).frame(height: 1) }
            Button {
                model.call(["op": "update_subscription", "uid": model.subscriptionUID]) { ok in if ok { model.load(verify: false) } }
            } label: {
                Label("更新节点", systemImage: "arrow.triangle.2.circlepath").frame(maxWidth: .infinity)
            }.buttonStyle(PanelButtonStyle(kind: .secondary, height: 38)).disabled(model.busy)
        }.padding(14)
            .background(Palette.surface, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.primary.opacity(0.06)))
            .shadow(color: .black.opacity(0.05), radius: 1, y: 1)
    }

    private var sidebarFooter: some View {
        let status = model.busy ? model.activity : (model.message.isEmpty ? "就绪 · 数据仅存本机" : model.message)
        return VStack(alignment: .leading, spacing: 6) {
            Button { restoring = true } label: {
                Label("恢复上次配置", systemImage: "arrow.uturn.backward").frame(maxWidth: .infinity, alignment: .leading)
            }.buttonStyle(PanelButtonStyle(kind: .ghost, height: 34)).disabled(model.busy || !model.hasBackup)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if model.busy { ProgressView().controlSize(.mini) }
                else { Circle().fill(model.error ? Palette.warning : Palette.successDot).frame(width: 6, height: 6) }
                Text(status).foregroundStyle(model.error ? Palette.warning : Palette.text2)
                    .lineLimit(4).textSelection(.enabled).help(status)
                Spacer(minLength: 4)
                Text("v\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")")
                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.text3)
            }.font(.system(size: 11)).padding(.horizontal, 8)
        }.padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 14)
            .overlay(alignment: .top) { Rectangle().fill(Palette.border).frame(height: 1) }
    }

    // MARK: - 主区

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 2) {
                Text("连接概览").font(.system(size: 22, weight: .semibold))
                Text(usingStatic ? (model.globalStatic ? "全部公网流量使用静态出口" : "国内直连 · 国外 TCP 使用静态出口") : "国内直连 · 国外经中转节点")
                    .font(.system(size: 13)).foregroundStyle(Palette.text2)
            }
            Spacer()
            Button { model.load() } label: { Label("刷新", systemImage: "arrow.clockwise") }
                .buttonStyle(PanelButtonStyle(kind: .secondary, height: 38)).disabled(model.busy)
            Menu {
                Button("检查更新…") { model.checkForUpdates(manual: true) }.disabled(model.busy)
                if model.serviceReady {
                    Button("重新安装网络服务") { model.registerService() }.disabled(model.running || !model.stateKnown || model.busy)
                }
            } label: {
                Image(systemName: "slider.horizontal.3").font(.system(size: 14, weight: .medium))
                    .frame(width: 44, height: 38).contentShape(Rectangle())
            }.menuStyle(.borderlessButton).fixedSize()
                .background(Palette.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Palette.border))
                .help("检查更新与网络服务").accessibilityLabel("设置")
        }
    }

    private func notice(icon: String, title: String, detail: [String], action: String, perform: @escaping () -> Void) -> some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: icon).font(.title2).foregroundStyle(Palette.warning)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 13, weight: .semibold))
                ForEach(detail.filter { !$0.isEmpty }, id: \.self) { line in
                    Text(line).font(.system(size: 12)).foregroundStyle(Palette.text2).textSelection(.enabled)
                }
            }
            Spacer(minLength: 5)
            Button(action, action: perform).buttonStyle(PanelButtonStyle(kind: .secondary, height: 34)).disabled(model.busy)
        }.padding(14).background(Palette.warningSoft, in: RoundedRectangle(cornerRadius: 14))
    }

    private var serviceNotice: some View {
        notice(icon: "lock.shield", title: model.serviceLabel,
               detail: ["安装时需要输入一次管理员密码；订阅和静态 IP 可以先离线管理。"],
               action: "安装网络服务") { model.registerService() }
    }

    private var recoveryNotice: some View {
        notice(icon: "exclamationmark.shield",
               title: model.recoveryNeeded ? "上次配置操作尚未恢复完成" : "网络服务状态需要确认",
               detail: [model.serviceError, model.recoveryNeeded ? "请先停止连接，确认服务停止后再选择出口或恢复配置。" : "未确认服务停止前，暂停切换订阅和启动新连接；你仍可尝试停止连接。"],
               action: "停止连接") { model.call(["op": "stop"]) { ok in if ok { model.load(verify: false) } } }
    }

    private var statusBadge: (String, Color, Color, Color) {
        if !model.stateKnown { return ("状态未知", Palette.warningSoft, Palette.warning, Palette.warning) }
        if model.connectionVerified { return ("已连接", Palette.successSoft, Palette.success, Palette.successDot) }
        if model.running { return ("待验证", Palette.warningSoft, Palette.warning, Palette.warning) }
        return ("未连接", Palette.chip, Palette.text2, Palette.idle)
    }

    private var hero: some View {
        let badge = statusBadge
        let hasIP = !model.exitIP.isEmpty
        return VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .bottom, spacing: 20) {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 8) {
                        PulseDot(color: badge.3, animate: model.connectionVerified).id(model.connectionVerified)
                        Text(badge.0).font(.system(size: 12, weight: .semibold))
                    }.foregroundStyle(badge.2).padding(.horizontal, 11).frame(height: 26)
                        .background(badge.1, in: Capsule())
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 8) {
                            Text("当前公网出口").font(.system(size: 13)).foregroundStyle(Palette.text3)
                            if model.checking { ProgressView().controlSize(.mini) }
                        }
                        HStack(spacing: 10) {
                            Text(hasIP ? model.exitIP : (!model.stateKnown ? "状态待确认" : (model.running ? "等待检测" : "尚未连接")))
                                .font(.system(size: 36, weight: hasIP ? .medium : .semibold, design: hasIP ? .monospaced : .default))
                                .textSelection(.enabled).lineLimit(1).minimumScaleFactor(0.7)
                            if hasIP {
                                Button { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(model.exitIP, forType: .string) } label: {
                                    Image(systemName: "doc.on.doc").frame(width: 28, height: 28).contentShape(Rectangle())
                                }.buttonStyle(.plain).foregroundStyle(Palette.text3).help("复制出口 IP").accessibilityLabel("复制出口 IP")
                            }
                        }
                        heroDetail
                    }
                }
                Spacer(minLength: 0)
                HStack(spacing: 10) {
                    if model.running && model.stateKnown {
                        Button("重新检测") { model.call(["op": "verify"]) }
                            .buttonStyle(PanelButtonStyle(kind: .ghost, height: 44)).disabled(model.busy)
                    }
                    if !model.relay.isEmpty {
                        if selectionSaved {
                            Label("已保存为默认", systemImage: "checkmark").font(.system(size: 13)).foregroundStyle(Palette.text2)
                                .labelStyle(SavedLabelStyle()).padding(.horizontal, 6)
                        } else {
                            Button { confirming = true } label: {
                                Label(model.running ? "应用所选出口" : "保存选择", systemImage: "bookmark")
                            }.buttonStyle(PanelButtonStyle(kind: .secondary, height: 44, radius: 12))
                                .disabled(model.busy || !model.stateKnown || model.recoveryNeeded)
                        }
                    }
                    if model.shouldOfferStop {
                        Button { model.call(["op": "stop"]) { ok in if ok { model.load(verify: false) } } } label: {
                            Label("断开连接", systemImage: "power").frame(minWidth: 96)
                        }.buttonStyle(PanelButtonStyle(kind: .danger, height: 44, radius: 12)).disabled(model.busy)
                    } else {
                        Button { model.call(["op": "start", "id": model.selected ?? "", "relay": model.relay]) } label: {
                            Label("开始连接", systemImage: "power").frame(minWidth: 96)
                        }.buttonStyle(PanelButtonStyle(kind: .primary, height: 44, radius: 12))
                            .disabled(model.busy || model.relay.isEmpty || model.subscriptionUID.isEmpty || !model.serviceReady || !model.stateKnown || model.recoveryNeeded)
                    }
                }
            }
            nodeSelector
        }.padding(.horizontal, 26).padding(.vertical, 24)
            .background(alignment: .topTrailing) { heroGlobe.offset(x: 96, y: -124) }
            .background(Palette.surface)
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(Palette.border))
            .shadow(color: .black.opacity(0.07), radius: 16, y: 8)
    }

    @ViewBuilder private var heroDetail: some View {
        if model.exitIP.isEmpty {
            Text(model.checking ? "正在通过当前线路检测…" : (!model.stateKnown ? "无法确认连接状态，请刷新或停止连接" : (model.running ? "检测后显示实际公网出口" : "选择订阅与中转节点（静态 IP 可选），然后开始连接")))
                .font(.system(size: 13)).foregroundStyle(Palette.text2)
        } else {
            HStack(spacing: 6) {
                Image(systemName: "mappin.and.ellipse").foregroundStyle(Palette.accent)
                Text(model.loadingExitLocation ? "正在查询地点…" : (model.exitLocation?.label ?? "地点暂不可用"))
                    .textSelection(.enabled)
                    .help(model.exitLocation?.help ?? "连接验证后单独查询 IP 归属地，查询失败不影响网络连接。")
                if model.exitLocation?.status == "stale" { Text("历史缓存").foregroundStyle(Palette.text3) }
                if let at = model.verifiedAt { Text("· 已实测 \(at.formatted(date: .omitted, time: .standard))").foregroundStyle(Palette.text3) }
            }.font(.system(size: 13)).foregroundStyle(Palette.text2)
        }
    }

    private var heroGlobe: some View {
        Canvas { context, size in
            let rect = CGRect(origin: .zero, size: size).insetBy(dx: 20, dy: 20)
            let shading = GraphicsContext.Shading.color(Palette.accent)
            context.stroke(Path(ellipseIn: rect), with: shading, lineWidth: 1)
            for width in [rect.width * 0.4, rect.width * 0.75] {
                context.stroke(Path(ellipseIn: CGRect(x: rect.midX - width / 2, y: rect.minY, width: width, height: rect.height)), with: shading, lineWidth: 1)
            }
            var lines = Path()
            lines.move(to: CGPoint(x: rect.midX, y: rect.minY)); lines.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
            lines.move(to: CGPoint(x: rect.minX, y: rect.midY)); lines.addLine(to: CGPoint(x: rect.maxX, y: rect.midY))
            for y in [rect.minY + rect.height * 0.25, rect.minY + rect.height * 0.75] {
                let half = rect.width / 2 * 0.866
                lines.move(to: CGPoint(x: rect.midX - half, y: y)); lines.addLine(to: CGPoint(x: rect.midX + half, y: y))
            }
            context.stroke(lines, with: shading, lineWidth: 1)
        }.frame(width: 400, height: 400).opacity(0.09).allowsHitTesting(false).accessibilityHidden(true)
    }

    /// 中转节点独占一行，完整显示节点名；右侧测当前节点或全部节点延迟。
    private var nodeSelector: some View {
        let delay = model.nodeDelays[model.relay]
        let testable = !model.busy && !model.subscriptionUID.isEmpty && !model.nodes.isEmpty && model.stateKnown && !model.recoveryNeeded
        return HStack(spacing: 10) {
            ZStack {
                HStack(spacing: 12) {
                    Image(systemName: "server.rack").font(.system(size: 15)).foregroundStyle(Palette.accent)
                        .frame(width: 34, height: 34).background(Palette.accentSoft, in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 2) {
                        Text("中转节点 · 点击切换").font(.system(size: 11)).foregroundStyle(Palette.text3)
                        Text(model.relay.isEmpty ? "请选择订阅和节点" : model.relay)
                            .font(.system(size: 14, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer(minLength: 8)
                    if !model.relay.isEmpty {
                        Label(model.nodeDelayLabel(model.relay), systemImage: "waveform.path.ecg")
                            .font(.system(size: 12, weight: .medium, design: .monospaced))
                            .foregroundStyle(delay?.status == "ok" ? Palette.success : Palette.text3)
                            .padding(.horizontal, 9).padding(.vertical, 4)
                            .background(delay?.status == "ok" ? Palette.successSoft : Palette.chip, in: Capsule()).fixedSize()
                    }
                    Image(systemName: "chevron.up.chevron.down").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.text3)
                }.padding(.horizontal, 10).frame(height: 54)
                    .background(Palette.surface, in: RoundedRectangle(cornerRadius: 12))
                    .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(nodeSelectorHovered && !model.busy ? Palette.accent.opacity(0.6) : Palette.border))
                    .accessibilityHidden(true)
                NodeSelectorControl(names: model.nodes,
                                    titles: model.nodes.map { "\($0)  ·  \(model.nodeDelayLabel($0))" },
                                    selection: $model.relay,
                                    enabled: !model.busy && !model.nodes.isEmpty,
                                    onChoose: { model.chooseRelay($0) })
            }.frame(height: 54)
                .onHover { nodeSelectorHovered = $0 }
                .opacity(model.busy || model.nodes.isEmpty ? 0.5 : 1)
                .help(model.relay.isEmpty ? "先选择机场订阅，再选择中转节点" : model.relay + "\n" + model.nodeDelayHelp(model.relay))
            if !model.latencyProgress.isEmpty {
                ProgressView().controlSize(.small)
                Text(model.latencyProgress).font(.system(size: 12).monospacedDigit()).foregroundStyle(Palette.text2).fixedSize()
                Button("取消测速") { model.cancelLatencyTest() }.buttonStyle(PanelButtonStyle(kind: .secondary, height: 40))
            } else {
                Button { model.testNodeLatencies(onlySelected: true) } label: { Label("测当前节点", systemImage: "speedometer") }
                    .buttonStyle(PanelButtonStyle(kind: .secondary, height: 40)).disabled(!testable || model.relay.isEmpty)
                Button { model.testNodeLatencies() } label: { Label("测全部节点", systemImage: "arrow.clockwise") }
                    .buttonStyle(PanelButtonStyle(kind: .tinted, height: 40)).disabled(!testable)
                    .help("测速全部节点；应用打开期间每 10 分钟也会自动测速。")
            }
        }
    }

    // MARK: - 静态 IP 库

    private func count(_ filter: Filter) -> Int { model.profiles.filter { matches($0, filter) }.count }
    private var expiredIDs: [String] {
        model.profiles.filter { $0.expiryStatus == .expired && !isConfigured($0) && $0.id != model.selected }.map(\.id)
    }

    private var library: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Text("静态 IP 库").font(.system(size: 17, weight: .semibold))
                Text("\(model.profiles.count)").font(.system(size: 12, weight: .medium, design: .monospaced)).foregroundStyle(Palette.text2)
                    .padding(.horizontal, 8).padding(.vertical, 1).background(Palette.chip, in: Capsule())
                Spacer()
                Button { importCSV() } label: { Label("导入 CSV", systemImage: "square.and.arrow.down") }
                    .buttonStyle(PanelButtonStyle(kind: .secondary, height: 38))
                Button { adding = true } label: { Label("添加", systemImage: "plus") }
                    .buttonStyle(PanelButtonStyle(kind: .tinted, height: 38))
            }.disabled(model.busy)
            if model.profiles.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "externaldrive.badge.plus").font(.system(size: 28, weight: .light)).foregroundStyle(Palette.text3)
                    Text("还没有保存的静态 IP").font(.headline)
                    Text("导入服务商 CSV，或添加代理地址和账号。也可以不用静态 IP，仅通过中转节点连接。").font(.caption).foregroundStyle(Palette.text2)
                    Button("导入 CSV") { importCSV() }.buttonStyle(PanelButtonStyle(kind: .tinted)).disabled(model.busy)
                }.frame(maxWidth: .infinity).padding(28)
                    .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Palette.border))
            } else {
                HStack(spacing: 10) {
                    HStack(spacing: 6) {
                        ForEach(Filter.allCases, id: \.self) { item in filterChip(item) }
                    }
                    Spacer(minLength: 8)
                    HStack(spacing: 8) {
                        Image(systemName: "magnifyingglass").foregroundStyle(Palette.text3)
                        TextField("搜索名称或 IP", text: $search).textFieldStyle(.plain).font(.system(size: 13))
                        if !search.isEmpty {
                            Button { search = "" } label: { Image(systemName: "xmark.circle.fill") }
                                .buttonStyle(.plain).foregroundStyle(Palette.text3).accessibilityLabel("清除搜索")
                        }
                    }.padding(.horizontal, 12).frame(width: 220, height: 36)
                        .background(Palette.chip, in: RoundedRectangle(cornerRadius: 10))
                }
                profileTable
            }
        }.alert("删除这个静态 IP？", isPresented: Binding(get: { profileToDelete != nil }, set: { if !$0 { profileToDelete = nil } }), presenting: profileToDelete) { profile in
            Button("取消", role: .cancel) { profileToDelete = nil }
            Button("删除", role: .destructive) {
                model.call(["op": "delete", "id": profile.id])
                profileToDelete = nil
            }
        } message: { profile in Text("删除「\(profile.name)」的本机记录和钥匙串密码。删除后，需重新添加才能再次选择这个出口。") }
        .alert("清理已过期的静态 IP？", isPresented: $purging) {
            Button("取消", role: .cancel) {}
            Button("全部删除", role: .destructive) { purgeExpired(expiredIDs) }
        } message: { Text("删除 \(expiredIDs.count) 个已过期静态 IP 的本机记录和钥匙串密码。正在使用的出口不会被删除。") }
    }

    private func filterChip(_ item: Filter) -> some View {
        let on = filter == item
        let (label, dot): (String, Color?) = switch item {
        case .all: ("全部", nil)
        case .ok: ("可用", Palette.successDot)
        case .soon: ("即将到期", Palette.dynamic(0xF79009, 0xFDB022))
        case .expired: ("已过期", Palette.dynamic(0xF04438, 0xF97066))
        }
        return Button { filter = item } label: {
            HStack(spacing: 6) {
                if let dot { Circle().fill(dot).frame(width: 7, height: 7) }
                Text(label).font(.system(size: 12, weight: .medium))
                Text("\(count(item))").font(.system(size: 11, design: .monospaced)).foregroundStyle(on ? Palette.accentText : Palette.text3)
            }.padding(.horizontal, 12).frame(height: 32)
                .foregroundStyle(on ? Palette.accentText : Palette.text)
                .background(on ? Palette.accentSoft : Palette.surface, in: Capsule())
                .overlay(Capsule().strokeBorder(on ? Palette.accentBorder : Palette.border))
                .contentShape(Capsule())
        }.buttonStyle(PressableStyle()).accessibilityAddTraits(on ? .isSelected : [])
    }

    private func sortButton(_ title: String, _ key: SortKey) -> some View {
        Button {
            if sortKey == key { sortAscending.toggle() } else { sortKey = key; sortAscending = true }
        } label: {
            HStack(spacing: 4) {
                Text(title)
                Image(systemName: sortKey == key ? (sortAscending ? "arrow.up" : "arrow.down") : "arrow.up.arrow.down")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(sortKey == key ? Palette.accentText : Palette.idle)
            }.contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func columns<A: View, B: View, C: View, D: View, E: View>(_ a: A, _ b: B, _ c: C, _ d: D, _ e: E) -> some View {
        HStack(spacing: 12) {
            a.frame(width: 22)
            b.frame(minWidth: 110, maxWidth: .infinity, alignment: .leading)
            c.frame(minWidth: 150, maxWidth: .infinity, alignment: .leading)
            d.frame(width: 64, alignment: .leading)
            e.frame(width: 170, alignment: .leading)
        }
    }

    private var profileTable: some View {
        let rows = filtered
        return VStack(spacing: 0) {
            HStack(spacing: 8) {
                columns(Color.clear, sortButton("名称", .name), Text("代理地址"), Text("协议"), sortButton("到期时间", .expiry))
                Color.clear.frame(width: 30)
            }.font(.system(size: 12, weight: .medium)).foregroundStyle(Palette.text3)
                .padding(.horizontal, 20).frame(height: 38)
                .background(Palette.subtle)
                .overlay(alignment: .bottom) { Rectangle().fill(Palette.border).frame(height: 1) }
            if rows.isEmpty {
                VStack(spacing: 10) {
                    Text("没有符合条件的静态 IP").font(.system(size: 13)).foregroundStyle(Palette.text3)
                    Button("清除筛选") { search = ""; filter = .all }.buttonStyle(PanelButtonStyle(kind: .secondary, height: 32))
                }.frame(maxWidth: .infinity).padding(.vertical, 36)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(rows.enumerated()), id: \.element.id) { index, profile in
                            profileRow(profile, last: index == rows.count - 1)
                        }
                    }
                }.frame(height: min(CGFloat(rows.count) * 53, 340))
            }
            HStack(spacing: 8) {
                HStack(spacing: 0) {
                    Text("显示 \(rows.count) / \(model.profiles.count) 个 · 当前选择 ")
                    Text(model.selectedProfile?.server ?? "不使用静态 IP")
                        .font(.system(size: 12, design: model.selectedProfile == nil ? .default : .monospaced)).foregroundStyle(Palette.text)
                }.lineLimit(1)
                Spacer()
                if !expiredIDs.isEmpty {
                    Button { purging = true } label: {
                        Label("清理已过期（\(expiredIDs.count)）", systemImage: "trash")
                    }.buttonStyle(.plain).foregroundStyle(Palette.danger).font(.system(size: 12, weight: .medium)).disabled(model.busy)
                }
            }.font(.system(size: 12)).foregroundStyle(Palette.text3)
                .padding(.horizontal, 20).frame(minHeight: 42)
                .overlay(alignment: .top) { Rectangle().fill(Palette.border).frame(height: 1) }
        }.background(Palette.surface)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Palette.border))
    }

    private func profileRow(_ profile: ExitProfile, last: Bool) -> some View {
        let on = model.selected == profile.id
        let status = profile.expiryStatus
        let expired = status == .expired
        let days = profile.daysLeft ?? 0
        let (pill, pillForeground, pillBackground): (String, Color, Color) = switch status {
        case .expired: ("已过期 \(-days) 天", Palette.danger, Palette.dangerSoft)
        case .soon: ("剩 \(days) 天", Palette.warning, Palette.warningSoft)
        case .ok: ("剩 \(days) 天", Palette.text3, .clear)
        case .unknown: ("", .clear, .clear)
        }
        return HStack(spacing: 8) {
            Button {
                guard !on else { return }
                model.selected = profile.id
                model.chooseProfile(profile.id)
            } label: {
                columns(
                    Circle().strokeBorder(on ? Palette.accent : (expired ? Palette.idle : Palette.text3), style: StrokeStyle(lineWidth: on ? 5 : 1.5, dash: expired && !on ? [3, 2] : []))
                        .frame(width: 18, height: 18),
                    HStack(spacing: 8) {
                        Text(profile.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                            .foregroundStyle(expired ? Palette.text3 : Palette.text)
                        if isConfigured(profile) {
                            Text(model.running ? "使用中" : "已保存").font(.system(size: 10, weight: .semibold)).foregroundStyle(Palette.accentText)
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background(Palette.accentSoft, in: RoundedRectangle(cornerRadius: 6)).fixedSize()
                        }
                    },
                    Text(profile.address).font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        .foregroundStyle(expired ? Palette.text3 : Palette.text2),
                    Text(profile.protocol.uppercased()).font(.system(size: 10, weight: .semibold)).tracking(0.4)
                        .foregroundStyle(Palette.text2).padding(.horizontal, 7).padding(.vertical, 3)
                        .background(Palette.chip, in: RoundedRectangle(cornerRadius: 6)),
                    HStack(spacing: 8) {
                        Text(profile.expiryLabel).font(.system(size: 12, design: .monospaced)).foregroundStyle(expired ? Palette.text3 : Palette.text2)
                        if !pill.isEmpty {
                            Text(pill).font(.system(size: 11, weight: .medium)).foregroundStyle(pillForeground)
                                .padding(.horizontal, 7).padding(.vertical, 1).background(pillBackground, in: Capsule()).fixedSize()
                        }
                    }
                ).padding(.horizontal, 8).frame(minHeight: 46).contentShape(Rectangle())
            }.buttonStyle(PressableStyle())
                .disabled(model.busy || (expired && !on))
                .help(expired ? "已过期，不能选择；如已续费请编辑到期时间。" : profile.name)
                .accessibilityAddTraits(on ? .isSelected : [])
            Menu {
                Button("编辑") { editing = profile }
                Button("删除", role: .destructive) { profileToDelete = profile }
            } label: { Image(systemName: "ellipsis").font(.system(size: 13, weight: .semibold)) }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 30, height: 30)
                .disabled(model.busy).accessibilityLabel("更多操作：\(profile.name)")
        }.padding(.horizontal, 12).padding(.vertical, 3)
            .background(on ? Palette.selected : Palette.surface)
            .overlay(alignment: .bottom) { if !last { Rectangle().fill(Palette.divider).frame(height: 1) } }
            .contextMenu {
                Button("编辑") { editing = profile }
                Button("删除", role: .destructive) { profileToDelete = profile }
            }
    }

    // MARK: - 出口设置

    /// 「使用静态 IP」跟随列表选择，关闭即仅用中转节点出口；在列表中点选静态 IP 也会自动开启。
    private var exitSettings: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("出口设置").font(.system(size: 17, weight: .semibold))
                Text("出口路由与环境一致性").font(.system(size: 13)).foregroundStyle(Palette.text3)
            }
            // 左列决定流量走哪个出口，右列让本机环境与出口所在地一致。
            Grid(horizontalSpacing: 0, verticalSpacing: 0) {
                GridRow {
                    settingRow("使用静态 IP",
                               detail: usingStatic ? (model.globalStatic ? "全部公网流量经静态出口" : "国外 TCP 经静态出口，国内直连") : "已关闭，仅通过中转节点出口",
                               isOn: usingStatic, enabled: !locked && !(model.profiles.isEmpty && !usingStatic)) { setUsingStatic(!usingStatic) }
                        .help("关闭后仅通过中转节点连接；已连接时立即切换并验证，失败自动恢复。")
                    settingRow("时区跟随出口",
                               detail: model.appliedTimezone.isEmpty ? "系统时区与出口所在地保持一致" : "已设为 \(model.appliedTimezone)",
                               isOn: model.syncTimezone, enabled: !locked) { model.setSyncTimezone(!model.syncTimezone) }
                        .help("开启后连接期间把系统时区设为出口 IP 所在地时区（暂停“自动设置时区”），刷新网页即可生效（个别长时间未重启的 Chrome 需重启）；菜单栏时钟也会随之改变。关闭、停止连接或重启电脑后恢复原设置。")
                }
                Rectangle().fill(Palette.divider).frame(height: 1).gridCellColumns(2)
                GridRow {
                    settingRow("国内也走静态 IP",
                               detail: usingStatic ? "国内网站也经静态出口，关闭则直连更快" : "需先开启「使用静态 IP」",
                               isOn: model.globalStatic, enabled: !locked && (usingStatic || model.globalStatic)) { model.setGlobalStatic(!model.globalStatic) }
                        .help("开启后除本机和局域网外全部经静态 IP 出口；静态 IP 不支持 UDP，公网 UDP（含微信通话、WebRTC）一律拦截。仅在使用静态 IP 时生效。")
                    settingRow("Chrome 英文语言",
                               detail: "浏览器界面与请求语言设为英文",
                               isOn: model.browserLanguage, enabled: !model.busy) { languageTarget = !model.browserLanguage }
                        .help("开启后 Chrome 网页语言（navigator.language、Accept-Language）与界面改为 en-US；关闭恢复原设置。切换时会退出并重开 Chrome，标签页自动恢复。")
                }
                Rectangle().fill(Palette.divider).frame(height: 1).gridCellColumns(2)
                GridRow {
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("直连白名单").font(.system(size: 13, weight: .semibold))
                            Text(model.directWhitelist.isEmpty ? "命中的网站与 IP 用本机网络直连，不经静态 IP 和中转节点" : "\(model.directWhitelist.count) 条 · " + model.directWhitelist.prefix(3).joined(separator: "、") + (model.directWhitelist.count > 3 ? "…" : ""))
                                .font(.system(size: 11)).foregroundStyle(Palette.text2).lineLimit(1).truncationMode(.tail)
                        }
                        Spacer(minLength: 8)
                        Button("编辑") { editingWhitelist = true }.controlSize(.small).disabled(locked)
                    }.padding(.horizontal, 16).padding(.vertical, 11)
                        .frame(maxWidth: .infinity, alignment: .leading).gridCellColumns(2)
                        .help("填入的域名（含子域名）与 IP/网段在所有模式下都直接使用本机网络，TCP 与 UDP 均放行，域名用国内 DNS 解析。")
                }
            }.background(Palette.surface, in: RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Palette.border))
        }.alert(languageTarget == true ? "把 Chrome 语言改为英文？" : "恢复 Chrome 原来的语言？", isPresented: Binding(get: { languageTarget != nil }, set: { if !$0 { languageTarget = nil } })) {
            Button("取消", role: .cancel) { languageTarget = nil }
            Button("退出并重开 Chrome") {
                if let target = languageTarget { model.setBrowserLanguage(target) }
                languageTarget = nil
            }
        } message: { Text("需要先退出 Chrome 才能修改语言，改完会重新打开并恢复标签页。未保存的网页表单内容可能丢失。") }
    }

    private func settingRow(_ title: String, detail: String, isOn: Bool, enabled: Bool, action: @escaping () -> Void) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(detail).font(.system(size: 11)).foregroundStyle(Palette.text2).lineLimit(1)
            }
            Spacer(minLength: 8)
            Toggle(title, isOn: Binding(get: { isOn }, set: { _ in action() }))
                .labelsHidden().toggleStyle(.switch).controlSize(.small).tint(Palette.accent)
        }.padding(.horizontal, 16).padding(.vertical, 11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .disabled(!enabled).opacity(enabled ? 1 : 0.55)
    }

    private func setUsingStatic(_ on: Bool) {
        if on {
            guard model.selected == nil else { return }
            let configured = model.profiles.first(where: isConfigured)
            let usable = model.profiles.filter { $0.expiryStatus != .expired }
            let target = model.profiles.first { $0.id == lastProfileID } ?? configured ?? filtered.first { $0.expiryStatus != .expired } ?? usable.first ?? model.profiles.first
            guard let target else { return }
            model.selected = target.id
            model.chooseProfile(target.id)
        } else {
            guard let current = model.selected else { return }
            lastProfileID = current
            model.selected = nil
            model.chooseProfile(nil)
        }
    }

    /// 逐个删除（后端一次只处理一个操作），任一失败即停止并保留错误信息。
    private func purgeExpired(_ ids: [String]) {
        guard let id = ids.first else { return }
        model.call(["op": "delete", "id": id]) { ok in if ok { purgeExpired(Array(ids.dropFirst())) } }
    }

    private func selectSubscription(_ item: Subscription) {
        model.call(["op": "select_subscription", "uid": item.uid])
    }

    private func canDeleteSubscription(_ item: Subscription) -> Bool {
        !model.busy && model.stateKnown && !model.recoveryNeeded &&
        model.subscriptions.contains { $0.uid == item.uid } &&
        !(model.running && item.uid == model.subscriptionUID)
    }

    /// 只在静态 IP 被删除时清除选择；搜索过滤不改变选择，否则会被当作「不使用静态 IP」。
    private func reconcileSelection() {
        if let id = model.selected, !model.profiles.contains(where: { $0.id == id }) { model.selected = nil }
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

struct SavedLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            configuration.icon.foregroundStyle(Palette.success).font(.system(size: 12, weight: .semibold))
            configuration.title
        }
    }
}

struct WhitelistView: View {
    @ObservedObject var model: Model
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    private var entries: [String] {
        text.split(whereSeparator: { $0.isNewline || $0 == "," || $0 == "，" || $0 == " " })
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("直连白名单").font(.title2.bold())
            Text("每行一个域名、网址或 IP/网段。命中的流量用本机网络直连，不经静态 IP 和中转节点。")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $text)
                .font(.system(size: 13, design: .monospaced)).frame(height: 220)
                .scrollContentBackground(.hidden).padding(6)
                .background(Palette.surface, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Palette.border))
            Text("例：example.com（含所有子域名）、https://a.example.com/path、203.0.113.5、203.0.113.0/24。已连接时保存会立即重新应用并验证。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if model.error { Text(model.message).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Text("\(entries.count) 条").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("取消") { dismiss() }
                Button("保存") { model.setWhitelist(entries) { ok in if ok { dismiss() } } }
                    .buttonStyle(.borderedProminent)
            }.disabled(model.busy)
        }.padding(24).frame(width: 480)
            .onAppear { text = model.directWhitelist.joined(separator: "\n") }
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
            .defaultSize(width: 1180, height: 880)
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
