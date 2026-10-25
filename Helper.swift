import Foundation
import Darwin

private final class DelayProbeResults {
    private let lock = NSLock()
    private var values: [[String: Any]]
    init(names: [String]) { values = names.map { ["name": $0, "status": "error"] } }
    func set(_ value: [String: Any], at index: Int) { lock.lock(); defer { lock.unlock() }; values[index] = value }
    func snapshot() -> [[String: Any]] { lock.lock(); defer { lock.unlock() }; return values }
}

private final class DelayProbeOutput {
    var data = Data()
}

final class NetworkService: NSObject, StaticExitNetworkProtocol, NSXPCListenerDelegate {
    let queue = DispatchQueue(label: "local.staticexit.network.operations")
    let root = URL(fileURLWithPath: networkServiceRoot)
    let policy: [String: Any]
    let requirement: String
    var child: pid_t = 0
    var active: [String: Any]?
    var lastError = ""
    var timer: DispatchSourceTimer?
    let controllerSecret = (0..<4).map { _ in UUID().uuidString.replacingOccurrences(of: "-", with: "") }.joined()
    let environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/root", "LANG": "en_US.UTF-8"]
    var runtime: URL { root.appendingPathComponent("runtime") }
    var core: String { root.appendingPathComponent("mihomo").path }

    init(policy: [String: Any], requirement: String) {
        self.policy = policy; self.requirement = requirement; super.init()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in self?.refresh() }
        timer.resume(); self.timer = timer
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == uid_t(policy["uid"] as? Int ?? -1) else { return false }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: StaticExitNetworkProtocol.self)
        connection.exportedObject = self; connection.resume(); return true
    }
    func request(_ payload: Data, withReply reply: @escaping (Data) -> Void) {
        guard payload.count < 4_000_000 else { reply(jsonData(["ok": false, "error": "请求过大。"])); return }
        queue.async {
            do {
                guard let request = try JSONSerialization.jsonObject(with: payload) as? [String: Any], let op = request["op"] as? String else { throw NetworkFailure.message("请求格式不正确。") }
                self.refresh()
                var value: [String: Any]
                switch op {
                case "status": value = self.status()
                case "stop": try self.stop(); value = self.status()
                case "start", "apply":
                    guard let raw = request["config"] as? [String: Any] else { throw NetworkFailure.message("缺少配置。") }
                    var config = try restrictedConfiguration(raw)
                    config["secret"] = self.controllerSecret
                    try self.apply(config); value = self.status()
                case "api":
                    let path = request["path"] as? String ?? ""
                    guard ["/configs", "/proxies", "/rules", "/version"].contains(path), self.child > 0 else { throw NetworkFailure.message("内核未运行，或接口不受支持。") }
                    value = ["data": try self.api(path)]
                case "node_delays":
                    guard self.child > 0 else { throw NetworkFailure.message("请先连接，再测试节点延迟。") }
                    let names = try validatedNodeDelayNames(request, active: self.active)
                    let secret = self.controllerSecret
                    let socket = self.runtime.appendingPathComponent("controller.sock").path
                    // 测速只读内核接口，耗时可达数十秒；移出串行队列，避免挡住同时发起的连接、切换或停止。
                    DispatchQueue.global(qos: .utility).async {
                        reply(jsonData(["ok": true, "results": self.nodeDelays(names, secret: secret, socket: socket)]))
                    }
                    return
                default: throw NetworkFailure.message("服务不支持这个操作。")
                }
                value["ok"] = true; reply(jsonData(value))
            } catch { reply(jsonData(["ok": false, "error": error.localizedDescription])) }
        }
    }
    func refresh() {
        if child > 0 {
            var status: Int32 = 0
            if waitpid(child, &status, WNOHANG) == child {
                child = 0; active = nil
                lastError = "内核已经退出，连接已停止。请检查线路后重新连接。"
            }
        }
    }
    func status() -> [String: Any] {
        let routed = child > 0 && routeInterface() == "utun78"
        return ["running": child > 0, "tun": routed, "state_known": true, "service_status": "enabled", "mixed_port": 17896,
                "pid": Int(child), "service_pid": Int(getpid()), "service_error": child > 0 && !routed ? "内核运行中，但整机 TUN 路由未生效；请停止后检查其他 VPN。" : lastError]
    }
    func routeInterface() -> String {
        let text = String(data: (try? command("/sbin/route", ["-n", "get", "1.1.1.1"], timeout: 2)) ?? Data(), encoding: .utf8) ?? ""
        return text.split(separator: "\n").first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:") })?.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
    }
    func command(_ path: String, _ args: [String], input: Data? = nil, timeout: TimeInterval = 12) throws -> Data {
        let task = Process(); task.executableURL = URL(fileURLWithPath: path); task.arguments = args; task.environment = environment
        let output = Pipe(); task.standardOutput = output; task.standardError = FileHandle.nullDevice
        let dataPipe = Pipe(); task.standardInput = dataPipe
        try task.run()
        if let input { dataPipe.fileHandleForWriting.write(input) }; try? dataPipe.fileHandleForWriting.close()
        let done = DispatchSemaphore(value: 0)
        task.terminationHandler = { _ in done.signal() }
        // 输出大小受支持接口限制；独立读线程防止管道写满。
        let group = DispatchGroup(); group.enter()
        var bytes = Data()
        DispatchQueue.global().async { bytes = output.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            if task.isRunning { task.terminate() }; if done.wait(timeout: .now() + 2) == .timedOut { kill(task.processIdentifier, SIGKILL) }
            task.waitUntilExit(); group.wait(); throw NetworkFailure.message("内核操作超时。")
        }
        group.wait()
        guard task.terminationStatus == 0 else { throw NetworkFailure.message("内核校验或控制请求失败。") }
        return bytes
    }
    func api(_ path: String, body: [String: Any]? = nil, timeout: TimeInterval = 8) throws -> Any {
        let secret = active?["secret"] as? String ?? ""
        var args = ["-fsS", "--max-time", String(timeout), "--unix-socket", runtime.appendingPathComponent("controller.sock").path, "--header", "Authorization: Bearer " + secret, "http://localhost" + path]
        // 只允许服务内部对自己的固定配置路径重载。
        if let body {
            let file = runtime.appendingPathComponent("reload-request.json")
            try jsonData(body).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            args += ["-X", "PUT", "-H", "Content-Type: application/json", "--data-binary", "@" + file.path]
        }
        let result = try command("/usr/bin/curl", args, timeout: timeout + 1)
        if result.isEmpty { return [:] as [String: Any] }
        return try JSONSerialization.jsonObject(with: result)
    }
    func nodeDelays(_ names: [String], secret: String, socket: String) -> [[String: Any]] {
        let results = DelayProbeResults(names: names)
        // 名称已在串行队列中按当时运行的配置校验；测速期间内核若被切换，未完成的探测只会记为失败。
        let slots = DispatchSemaphore(value: nodeDelayConcurrency)
        let group = DispatchGroup()
        for (index, name) in names.enumerated() {
            slots.wait(); group.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { slots.signal(); group.leave() }
                self.probeNodeDelay(name, at: index, secret: secret, socket: socket, into: results)
            }
        }
        group.wait()
        return results.snapshot()
    }
    fileprivate func probeNodeDelay(_ name: String, at index: Int, secret: String, socket: String, into results: DelayProbeResults) {
        do {
            let task = Process(); task.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
            task.arguments = ["-q", "-sS", "--max-time", "5.3", "--connect-timeout", "1", "--proxy", "", "--noproxy", "*", "--path-as-is", "--max-filesize", "65536",
                              "--unix-socket", socket, "--header", "Authorization: Bearer " + secret,
                              "--write-out", "\n%{http_code}", "http://localhost" + nodeDelayPath(name)]
            task.environment = environment; task.standardInput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
            let pipe = Pipe(); task.standardOutput = pipe
            let done = DispatchSemaphore(value: 0)
            task.terminationHandler = { _ in done.signal() }
            do { try task.run() } catch { return }
            let output = DelayProbeOutput()
            let reader = DispatchGroup(); reader.enter()
            DispatchQueue.global().async { output.data = pipe.fileHandleForReading.readDataToEndOfFile(); reader.leave() }
            if done.wait(timeout: .now() + 5.5) == .timedOut {
                if task.isRunning { kill(task.processIdentifier, SIGKILL) }
                task.waitUntilExit(); reader.wait()
                results.set(["name": name, "status": "timeout"], at: index)
                return
            }
            reader.wait()
            guard let separator = output.data.lastIndex(of: 10),
                  let code = String(data: output.data.suffix(from: output.data.index(after: separator)), encoding: .utf8).flatMap(Int.init) else {
                results.set(nodeDelayResult(name: name, data: Data(), httpStatus: 0, exitCode: task.terminationStatus), at: index)
                return
            }
            results.set(nodeDelayResult(name: name, data: output.data.prefix(upTo: separator), httpStatus: code, exitCode: task.terminationStatus), at: index)
        }
    }
    func writeConfig(_ config: [String: Any], name: String) throws -> URL {
        try FileManager.default.createDirectory(at: runtime, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard trustedRootPath(runtime.path, directory: true) else { throw NetworkFailure.message("服务运行目录权限异常，已拒绝写入。") }
        for asset in ["geosite.dat", "Country.mmdb"] {
            let dst = runtime.appendingPathComponent(asset)
            if !FileManager.default.fileExists(atPath: dst.path) { try FileManager.default.copyItem(at: root.appendingPathComponent("geodata/" + asset), to: dst) }
            guard trustedRootPath(dst.path, directory: false) else { throw NetworkFailure.message("地理规则文件权限异常。") }
        }
        let path = runtime.appendingPathComponent(name)
        try jsonData(config).write(to: path, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        return path
    }
    func apply(_ config: [String: Any]) throws {
        let candidate = try writeConfig(config, name: "candidate.json")
        _ = try command(core, ["-t", "-d", runtime.path, "-f", candidate.path])
        if child > 0 {
            let previous = active
            do {
                _ = try api("/configs?force=true", body: ["path": candidate.path])
                active = config
                try waitReady()
                _ = try writeConfig(config, name: "active.json")
            } catch {
                if let previous {
                    do {
                        let rollback = try writeConfig(previous, name: "rollback.json")
                        _ = try api("/configs?force=true", body: ["path": rollback.path]); active = previous
                        try waitReady()
                    } catch {
                        try? stop()
                        throw NetworkFailure.message("配置应用及恢复均失败，已停止本应用的连接。")
                    }
                }
                throw error
            }
        } else {
            // 只检测冲突，不停止其他客户端或修改它们的配置。
            if routeInterface().hasPrefix("utun") || if_nametoindex("utun78") != 0 { throw NetworkFailure.message("检测到其他 VPN/TUN 正在接管网络。请先停止它，再开始连接。") }
            let path = try writeConfig(config, name: "active.json")
            try spawnCore(path); active = config
            do { try waitReady() } catch { try? stop(); throw error }
        }
        lastError = ""
    }
    func spawnCore(_ path: URL) throws {
        var actions: posix_spawn_file_actions_t?; posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)
        var attributes: posix_spawnattr_t?; posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        var defaults = sigset_t(); sigemptyset(&defaults); sigaddset(&defaults, SIGTERM); sigaddset(&defaults, SIGINT)
        var mask = sigset_t(); sigemptyset(&mask)
        posix_spawnattr_setsigdefault(&attributes, &defaults); posix_spawnattr_setsigmask(&attributes, &mask)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT))
        let arguments: [String] = [core, "-d", runtime.path, "-f", path.path]
        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { value in value.withCString { strdup($0) } }
        argv.append(nil)
        var envp: [UnsafeMutablePointer<CChar>?] = environment.map { item in (item.key + "=" + item.value).withCString { strdup($0) } }
        envp.append(nil)
        defer { for value in argv { free(value) }; for value in envp { free(value) } }
        var pid: pid_t = 0
        let code = argv.withUnsafeBufferPointer { args in envp.withUnsafeBufferPointer { env in
            posix_spawn(&pid, core, &actions, &attributes, args.baseAddress!, env.baseAddress!)
        } }
        guard code == 0 else { throw NetworkFailure.message("无法启动内置内核。") }
        child = pid
        guard getpgid(child) == getpgrp() else { try? stop(); throw NetworkFailure.message("内核进程组不匹配，已停止以保证退出清理。") }
    }
    func waitReady() throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 10
        while ProcessInfo.processInfo.systemUptime < deadline {
            refresh(); if child == 0 { throw NetworkFailure.message("内核启动失败，端口或 TUN 可能冲突。") }
            if let config = try? api("/configs", timeout: 0.5) as? [String: Any],
               let tun = config["tun"] as? [String: Any], tun["enable"] as? Bool == true,
               if_nametoindex("utun78") != 0, routeInterface() == "utun78" {
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: runtime.appendingPathComponent("controller.sock").path)
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        throw NetworkFailure.message("内核尚未就绪。")
    }
    func stop() throws {
        if child > 0 {
            let pid = child; kill(pid, SIGTERM)
            for _ in 0..<80 {
                var state: Int32 = 0
                if waitpid(pid, &state, WNOHANG) == pid { child = 0; break }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if child > 0 { kill(pid, SIGKILL); var state: Int32 = 0; waitpid(pid, &state, 0); child = 0 }
        }
        active = nil; lastError = ""
        try? FileManager.default.removeItem(at: runtime.appendingPathComponent("controller.sock"))
    }
}

// 启动信息来自安装包的 root 所有固定数据，不接受请求指定路径或身份。
func trustedRootPath(_ path: String, directory: Bool) -> Bool {
    var info = stat()
    guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & 0o022 == 0,
          info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) else { return false }
    return true
}
guard geteuid() == 0,
      ["/Library", "/Library/Application Support", networkServiceRoot, networkServiceRoot + "/geodata"].allSatisfy({ trustedRootPath($0, directory: true) }),
      [networkServiceRoot + "/policy.json", networkServiceRoot + "/mihomo", networkServiceRoot + "/geodata/geosite.dat", networkServiceRoot + "/geodata/Country.mmdb", "/Library/PrivilegedHelperTools/local.staticexit.network"].allSatisfy({ trustedRootPath($0, directory: false) }),
      let bytes = try? Data(contentsOf: URL(fileURLWithPath: networkServiceRoot + "/policy.json")),
      let policy = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
      let requirement = policy["client_requirement"] as? String,
      let allowedUID = policy["uid"] as? Int, allowedUID > 0, allowedUID <= Int(UInt32.max) else { exit(78) }
umask(0o077)
let service = NetworkService(policy: policy, requirement: requirement)
let listener = NSXPCListener(machServiceName: networkServiceName)
listener.setConnectionCodeSigningRequirement(requirement)
listener.delegate = service
signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: service.queue)
term.setEventHandler { try? service.stop(); exit(0) }; term.resume()
let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: service.queue)
interrupt.setEventHandler { try? service.stop(); exit(0) }; interrupt.resume()
listener.resume()
RunLoop.current.run()
