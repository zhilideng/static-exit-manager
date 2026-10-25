import Foundation

// 供本机真实订阅兼容性检查使用：仅规范化数据，不运行服务或更改网络。
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--normalize" {
    do {
        let source = URL(fileURLWithPath: CommandLine.arguments[2])
        let target = URL(fileURLWithPath: CommandLine.arguments[3])
        let raw = try JSONSerialization.jsonObject(with: Data(contentsOf: source)) as! [String: Any]
        let output = try restrictedConfiguration(raw)
        try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys, .withoutEscapingSlashes]).write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        exit(0)
    } catch { print(error.localizedDescription); exit(1) }
}

// 仅验证配置数据边界，不启动服务、内核或网络。
var passed = 0
func check(_ value: @autoclosure () -> Bool, _ message: String) {
    if !value() { fatalError(message) }; passed += 1
}
func fixture() -> [String: Any] {
    ["secret": String(repeating: "A", count: 48),
     "proxies": [["name": "美国二", "type": "trojan", "server": "relay.example.test", "port": 443, "password": "fixture"],
                 ["name": "静态IP出口", "type": "socks5", "server": "192.0.2.1", "port": 443, "username": "fixture", "password": "fixture", "udp": false, "dialer-proxy": "静态IP机场中转"]],
     "proxy-groups": [["name": "静态IP机场中转", "type": "select", "proxies": ["美国二"]]],
     "rules": staticExitRules, "dns": ["enable": true]]
}
func rejects(_ title: String, _ change: (inout [String: Any]) -> Void) {
    var input = fixture(); change(&input)
    do { _ = try restrictedConfiguration(input); fatalError("没有拒绝：" + title) }
    catch { passed += 1 }
}
func changeNode(_ input: inout [String: Any], _ index: Int = 0, _ change: (inout [String: Any]) -> Void) {
    var nodes = input["proxies"] as! [[String: Any]]; change(&nodes[index]); input["proxies"] = nodes
}
// 仅中转节点：不含静态出口，规则以中转组为 MATCH 出口；混用两种模式的配置一律拒绝。
func relayOnlyFixture() -> [String: Any] {
    var input = fixture()
    input["proxies"] = [(input["proxies"] as! [[String: Any]])[0]]
    input["rules"] = relayOnlyRules
    return input
}
let relayOnlyOutput = try restrictedConfiguration(relayOnlyFixture())
check(relayOnlyOutput["rules"] as? [String] == relayOnlyRules, "仅中转规则发生变化")
check(relayOnlyRules.contains("NETWORK,UDP,REJECT") && relayOnlyRules.last == "MATCH,静态IP机场中转", "仅中转模式未拒绝国外 UDP 或出口不对")
check((relayOnlyOutput["proxies"] as! [[String: Any]]).count == 1, "仅中转模式节点数量不对"); passed += 3
rejects("仅中转规则却带静态出口") { $0["rules"] = relayOnlyRules }
rejects("静态出口规则却缺少静态出口") { $0["proxies"] = [($0["proxies"] as! [[String: Any]])[0]] }
do { var input = relayOnlyFixture(); input["rules"] = staticExitRules.dropLast() + ["MATCH,DIRECT"]
     _ = try restrictedConfiguration(input); fatalError("没有拒绝：国外流量直连") } catch { passed += 1 }
let output = try restrictedConfiguration(fixture())
check(output["mixed-port"] as? Int == 17896, "监听端口不固定")
check(output["mode"] as? String == "rule", "规则模式不固定")
check(output["ipv6"] as? Bool == false, "IPv6 不固定")
check(output["external-controller-unix"] as? String == networkServiceRoot + "/runtime/controller.sock", "控制 socket 不固定")
check(output["rules"] as? [String] == staticExitRules, "规则发生变化")
check(output["tcp-concurrent"] as? Bool == true, "未启用 TCP 并发拨号")
check(output["unified-delay"] as? Bool == true, "延迟未采用预热后的统一计时方式")
let outputTUN = output["tun"] as! [String: Any]
check(outputTUN["dns-mode"] as? String == "native", "macOS 系统 DNS 未注册到 TUN")
check(outputTUN["dns-hijack"] as? [String] == ["any:53", "tcp://any:53"], "DNS 劫持未覆盖 UDP 和 TCP")
let outputDNS = output["dns"] as! [String: Any]
check(outputDNS["default-nameserver"] as? [String] == ["223.5.5.5"], "基础 DNS 被更改")
check(outputDNS["proxy-server-nameserver"] as? [String] == ["https://223.5.5.5/dns-query#DIRECT"], "中转域名解析没有显式直连")
check((outputDNS["nameserver-policy"] as? [String: [String]])?["geosite:cn"] == ["https://223.5.5.5/dns-query#DIRECT"], "国内 DNS 没有显式直连")
rejects("curl 配置注入") { $0["secret"] = String(repeating: "A", count: 32) + "\"\noutput=/tmp/injected" }
rejects("过短控制 token") { $0["secret"] = "abc" }
rejects("额外任意配置路径") { $0["external-ui"] = "/etc" }
rejects("改写国外规则") { $0["rules"] = ["MATCH,DIRECT"] + staticExitRules }
rejects("重排国内规则") { var r = staticExitRules; r.swapAt(11,15); $0["rules"] = r }
rejects("组 provider 文件引用") { $0["proxy-groups"] = [["name": "静态IP机场中转", "type": "select", "proxies": ["美国二"], "use": ["file"]]] }
rejects("布尔值端口") { changeNode(&$0) { $0["port"] = true } }
rejects("小数端口") { changeNode(&$0) { $0["port"] = 443.5 } }
rejects("超范围端口") { changeNode(&$0) { $0["port"] = 65536 } }
rejects("重复节点名") { changeNode(&$0) { $0["name"] = "静态IP出口" } }
rejects("保留节点名") { changeNode(&$0) { $0["name"] = "DIRECT" } }
rejects("无效服务器") { changeNode(&$0) { $0["server"] = "example.test\rhost" } }
rejects("中转递归链") { changeNode(&$0) { $0["dialer-proxy"] = "静态IP出口" } }
rejects("静态出口绕过中转") { changeNode(&$0, 1) { $0["dialer-proxy"] = "DIRECT" } }
rejects("插件") { changeNode(&$0) { $0["plugin"] = "/bin/sh" } }
rejects("私钥文件") { changeNode(&$0) { $0["private-key"] = "/etc/passwd" } }
rejects("未知嵌套传输字段") { changeNode(&$0) { $0["ws-opts"] = ["path": "/", "ca": "/etc/passwd"] } }
rejects("传输中再次嵌套路径对象") { changeNode(&$0) { $0["ws-opts"] = ["path": ["file": "/etc/passwd"]] } }
rejects("HTTP 头换行") { changeNode(&$0) { $0["ws-opts"] = ["headers": ["Host": "example.test\r\nInjected: x"]] } }
rejects("ECH 嵌套文件") { changeNode(&$0) { $0["ech-opts"] = ["config": ["path": "/etc/passwd"]] } }
rejects("普通字段对象") { changeNode(&$0) { $0["password"] = ["command": "/bin/sh"] } }
var edited = fixture()
edited["mixed-port"] = 22; edited["allow-lan"] = true; edited["bind-address"] = "0.0.0.0"
edited["external-controller"] = "0.0.0.0:8080"; edited["mode"] = "direct"
edited["tcp-concurrent"] = false
edited["unified-delay"] = false
edited["tun"] = ["file-descriptor": 123, "enable": false, "dns-mode": "disabled", "dns-hijack": []] as [String: Any]
edited["dns"] = ["listen": "0.0.0.0:53", "nameserver": ["https://bad.example.test"], "arbitrary": ["path": "/etc/passwd"]]
changeNode(&edited, 1) { $0["udp"] = true }
let cleaned = try restrictedConfiguration(edited)
check(cleaned["external-controller"] == nil, "客户端开启了 TCP 控制器")
check(cleaned["allow-lan"] as? Bool == false && cleaned["bind-address"] as? String == "127.0.0.1", "客户端改写了监听地址")
check((cleaned["tun"] as? [String: Any])?["file-descriptor"] == nil, "客户端控制了 TUN 文件描述符")
check((cleaned["tun"] as? [String: Any])?["dns-mode"] as? String == "native", "客户端关闭了系统 DNS 接管")
check((cleaned["tun"] as? [String: Any])?["dns-hijack"] as? [String] == ["any:53", "tcp://any:53"], "客户端关闭了 DNS 劫持")
check((cleaned["dns"] as? [String: Any])?["nameserver"] as? [String] == ["https://1.1.1.1/dns-query"], "客户端控制了 DNS")
check((cleaned["proxies"] as? [[String: Any]])?[1]["udp"] as? Bool == false, "静态 UDP 没有禁用")
check(cleaned["tcp-concurrent"] as? Bool == true, "客户端关闭了 TCP 并发拨号")
check(cleaned["unified-delay"] as? Bool == true, "客户端关闭了统一延迟计时")
check((cleaned["dns"] as? [String: Any])?["proxy-server-nameserver"] as? [String] == ["https://223.5.5.5/dns-query#DIRECT"], "客户端改写了中转域名解析线路")
var normalTransport = fixture()
changeNode(&normalTransport) { node in
    node["type"] = "vmess"; node["uuid"] = "fixture"; node["alterId"] = 0; node["tls"] = true
    node["ws-opts"] = ["path": "/proxy", "headers": ["Host": "example.test"], "max-early-data": 1024]
}
_ = try restrictedConfiguration(normalTransport); passed += 1
var ech = fixture(); changeNode(&ech) { $0["ech-opts"] = ["enable": true, "query-server-name": "example.test"] }
_ = try restrictedConfiguration(ech); passed += 1
// 输入来自 JSON，NSNumber 的 true 不能作为 Int 端口绕过。
var jsonPort = fixture(); changeNode(&jsonPort) { $0["port"] = true }
let decoded = try JSONSerialization.jsonObject(with: JSONSerialization.data(withJSONObject: jsonPort)) as! [String: Any]
do { _ = try restrictedConfiguration(decoded); fatalError("JSON 布尔端口通过") } catch { passed += 1 }

// 节点延迟控制接口的权限和路径边界；仅使用内存样例，不发起网络请求。
func rejectsDelay(_ request: [String: Any], active: [String: Any]? = output) {
    do { _ = try validatedNodeDelayNames(request, active: active); fatalError("延迟请求未被拒绝") }
    catch { passed += 1 }
}
let validDelayNames = try validatedNodeDelayNames(["op": "node_delays", "names": ["美国二"]], active: output)
check(validDelayNames == ["美国二"], "有效中转节点无法测试")
var manyNodes = output
var manyProxies = manyNodes["proxies"] as! [[String: Any]]
let template = manyProxies.first { $0["name"] as? String == "美国二" }!
let allDelayNames = (1...68).map { "批量节点\($0)" }
manyProxies += allDelayNames.map { name in var node = template; node["name"] = name; return node }
manyNodes["proxies"] = manyProxies
let validAllDelayNames = try validatedNodeDelayNames(["op": "node_delays", "names": allDelayNames], active: manyNodes)
check(validAllDelayNames == allDelayNames, "整订阅 68 个节点无法一次测试")
rejectsDelay(["op": "node_delays", "names": []])
rejectsDelay(["op": "node_delays", "names": ["美国二", "美国二"]])
rejectsDelay(["op": "node_delays", "names": (0...nodeDelayMaxNames).map { "节点\($0)" }])
rejectsDelay(["op": "node_delays", "names": [true]])
rejectsDelay(["op": "node_delays", "names": ["美国二"], "url": "https://example.test/private"])
rejectsDelay(["op": "node_delays", "names": ["美国二"]], active: nil)
for name in ["静态IP出口", "静态IP机场中转", "DIRECT", "REJECT", "GLOBAL", "其他订阅节点", "../configs?force=true", "美国二\n"] {
    rejectsDelay(["op": "node_delays", "names": [name]])
}
let unusualName = "../美国/香港?x=1&url=https://example.test/#%🇺🇸"
var unusual = output
var unusualNodes = unusual["proxies"] as! [[String: Any]]
unusualNodes[0]["name"] = unusualName; unusual["proxies"] = unusualNodes
let unusualDelayNames = try validatedNodeDelayNames(["op": "node_delays", "names": [unusualName]], active: unusual)
check(unusualDelayNames == [unusualName], "合法的特殊字符节点名被拒绝")
let delayPath = nodeDelayPath(unusualName)
let encodedName = delayPath.components(separatedBy: "/")[2]
check(encodedName.removingPercentEncoding == unusualName, "节点名编码不能无损恢复")
check(!encodedName.contains("/") && !encodedName.contains("?") && !encodedName.contains("#") && !encodedName.contains(".."), "节点名能够注入 API 路径")
check(delayPath.components(separatedBy: "?").count == 2 && delayPath.hasSuffix("?url=http%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=5000"), "测速 URL 或 5 秒时限不正确")
func delayResult(_ json: String, code: Int = 200, exitCode: Int32 = 0) -> [String: Any] {
    nodeDelayResult(name: "美国二", data: Data(json.utf8), httpStatus: code, exitCode: exitCode)
}
check(delayResult("{\"delay\":168}")["delay_ms"] as? Int == 168, "没有接受有效延迟")
check(delayResult("{\"delay\":4999}")["delay_ms"] as? Int == 4999, "5 秒范围内的有效延迟被拒绝")
for invalid in ["{\"delay\":0}", "{\"delay\":true}", "{\"delay\":1.5}", "{\"delay\":5001}", "{\"delay\":\"168\"}", "not json"] {
    check(delayResult(invalid)["status"] as? String == "error", "接受了无效延迟响应")
}
check(delayResult("{\"message\":\"fixture-secret\"}", code: 504)["status"] as? String == "timeout", "没有识别内核超时")
check(delayResult("", code: 0, exitCode: 28)["status"] as? String == "timeout", "没有识别 curl 超时")
let failedDelay = delayResult("{\"message\":\"fixture-secret https://relay.example.test/private\"}", code: 503)
check(Set(failedDelay.keys) == Set(["name", "status"]) && failedDelay["status"] as? String == "error", "延迟失败透传了内核原始错误")
print("配置边界测试通过：\(passed) 项；未启动网络。")

// 可选集成检查：在项目目录用 --check-local-subscriptions 读取本机三个订阅。
// 静态代理使用占位认证；只执行内核 -t，不读取钥匙串，不启动 TUN。
if CommandLine.arguments.contains("--check-local-subscriptions") {
    let program = #"""
import sys,json,pathlib,subprocess,tempfile,shutil,os
from unittest.mock import patch
import backend as b
checker=sys.argv[1]
verge=pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
def yaml(p):
 return json.loads(subprocess.check_output(['/usr/bin/ruby','-ryaml','-rjson','-e','puts YAML.load_file(ARGV[0]).to_json',str(p)],text=True))
items=[i for i in yaml(verge/'profiles.yaml').get('items',[]) if i.get('type') in ('remote','local')]
static={'name':'静态IP出口','type':'socks5','server':'192.0.2.1','port':443,'username':'fixture','password':'fixture','udp':False,'dialer-proxy':'静态IP机场中转'}
passed=0
with tempfile.TemporaryDirectory(prefix='static-exit-real-policy-') as tmp:
 root=pathlib.Path(tmp)
 for asset in ('Country.mmdb','geosite.dat'):shutil.copy2(pathlib.Path('vendor/geodata')/asset,root/asset)
 for idx,item in enumerate(items):
  try:
   config=b.normalize_subscription(yaml(verge/'profiles'/item['file']))
   with patch.object(b,'static_proxy',return_value=static):
    generated=b.generate_config(config,{},b.available_nodes(config)[0],{'controller_secret':'A'*48})
   raw=root/f'{idx}-raw.json';clean=root/f'{idx}-clean.json'
   raw.write_text(json.dumps(generated,ensure_ascii=False));raw.chmod(0o600)
   result=subprocess.run([checker,'--normalize',str(raw),str(clean)],text=True,capture_output=True,timeout=20)
   if result.returncode:raise ValueError('Swift 策略拒绝配置：'+result.stdout.strip())
   result=subprocess.run([str(pathlib.Path('vendor/mihomo').resolve()),'-t','-d',str(root),'-f',str(clean)],text=True,capture_output=True,timeout=30,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(root)})
   if result.returncode:raise ValueError('内核 -t 校验失败；为避免凭据泄露，不输出原始内核日志。')
   passed+=1;print(item.get('name','订阅'),': backend → Swift policy → mihomo -t 通过；节点',len(config['proxies']))
  except Exception as error:print(item.get('name','订阅'),':',str(error))
print('真实订阅校验通过',passed,'/',len(items))
sys.exit(0 if items and passed==len(items) else 1)
"""#
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    process.arguments = ["-c", program, CommandLine.arguments[0]]
    try process.run(); process.waitUntilExit()
    if process.terminationStatus != 0 { exit(process.terminationStatus) }
}
