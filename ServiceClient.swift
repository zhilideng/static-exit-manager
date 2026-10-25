import Foundation
import AppKit
import Security
import Darwin

private func installedPolicy() -> [String: Any]? {
    let url = URL(fileURLWithPath: networkServiceRoot).appendingPathComponent("policy.json")
    for path in ["/Library", "/Library/Application Support", networkServiceRoot, url.path] {
        var st = stat()
        guard lstat(path, &st) == 0, st.st_uid == 0, st.st_mode & 0o022 == 0,
              st.st_mode & S_IFMT == (path == url.path ? S_IFREG : S_IFDIR) else { return nil }
    }
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
          (attrs[.ownerAccountID] as? NSNumber)?.intValue == 0,
          ((attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0) & 0o022 == 0,
          let data = try? Data(contentsOf: url),
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    return value
}

func serviceRegistrationStatus() -> String {
    guard let policy = installedPolicy(), let requirement = policy["client_requirement"] as? String else { return "notRegistered" }
    var rule: SecRequirement?
    var code: SecCode?
    guard SecRequirementCreateWithString(requirement as CFString, [], &rule) == errSecSuccess,
          SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCheckValidity(code, [], rule) == errSecSuccess else { return "notRegistered" }
    return "enabled"
}

/// 经 macOS 管理员授权运行应用内的安装脚本。脚本以 root 读取这份应用的实际签名写入服务策略，
/// 因此服务只接受当前用户与这份应用，换电脑、换用户或重新构建后都在本机重新安装即可。
func registerNetworkService() -> [String: Any] {
    guard let script = Bundle.main.resourceURL?.appendingPathComponent("service/install.sh"),
          FileManager.default.fileExists(atPath: script.path) else {
        return ["ok": false, "error": "应用内缺少网络服务安装脚本，请重新安装完整应用。"]
    }
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    // 路径和 uid 以参数传入，经 quoted form 转义，避免拼接进 AppleScript 源码。
    task.arguments = ["-e", "on run argv",
                      "-e", "do shell script \"/bin/sh \" & quoted form of item 1 of argv & \" \" & quoted form of item 2 of argv & \" \" & item 3 of argv with prompt \"静态出口管理器需要安装网络服务。\" with administrator privileges",
                      "-e", "end run", script.path, Bundle.main.bundlePath, String(getuid())]
    let errors = Pipe()
    task.standardOutput = FileHandle.nullDevice
    task.standardError = errors
    do { try task.run() } catch { return ["ok": false, "error": "无法请求管理员授权。"] }
    let detail = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    task.waitUntilExit()
    if task.terminationStatus == 0 { return ["ok": true, "message": "网络服务已安装。"] }
    if detail.contains("-128") { return ["ok": false, "error": "已取消安装网络服务。"] }
    return ["ok": false, "error": "网络服务安装失败，请重试。"]
}

func serviceRequest(_ request: [String: Any]) -> [String: Any] {
    let registration = serviceRegistrationStatus()
    guard registration == "enabled", let policy = installedPolicy(), let helperRequirement = policy["helper_requirement"] as? String else {
        if request["op"] as? String == "status" {
            let exists = FileManager.default.fileExists(atPath: networkServiceRoot + "/policy.json") || FileManager.default.fileExists(atPath: "/Library/PrivilegedHelperTools/" + networkServiceName)
            return ["ok": true, "running": false, "tun": false, "state_known": !exists, "service_status": registration, "mixed_port": 17896,
                    "service_error": exists ? "已安装的服务与本应用版本不匹配，当前运行状态未知；请安装配套网络服务。" : ""]
        }
        return ["ok": false, "error": "请先安装本版本的网络服务，再启动连接。"]
    }
    let connection = NSXPCConnection(machServiceName: networkServiceName, options: .privileged)
    connection.remoteObjectInterface = NSXPCInterface(with: StaticExitNetworkProtocol.self)
    connection.setCodeSigningRequirement(helperRequirement)
    let signal = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var result: [String: Any]?
    func finish(_ value: [String: Any]) {
        lock.lock(); defer { lock.unlock() }
        if result == nil { result = value; signal.signal() }
    }
    connection.invalidationHandler = { finish(["ok": false, "error": "网络服务连接已中断，请确认安装完成后重试。"] ) }
    connection.resume()
    guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
        finish(["ok": false, "error": "无法连接网络服务，请重新安装本版本网络服务后重试。"])
    }) as? StaticExitNetworkProtocol else {
        connection.invalidate(); return ["ok": false, "error": "网络服务接口不可用。"]
    }
    proxy.request(jsonData(request)) { data in
        let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        finish(value ?? ["ok": false, "error": "网络服务返回格式异常。"])
    }
    if signal.wait(timeout: .now() + 70) == .timedOut { finish(["ok": false, "error": "网络服务响应超时，请刷新确认当前连接状态。"] ) }
    lock.lock(); let answer = result ?? ["ok": false, "error": "网络服务未响应。"] ; lock.unlock()
    connection.invalidate()
    return answer
}
