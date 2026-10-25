import Foundation

let networkServiceName = "local.staticexit.network"
let networkServiceRoot = "/Library/Application Support/StaticExitManagerService"

@objc protocol StaticExitNetworkProtocol {
    func request(_ payload: Data, withReply reply: @escaping (Data) -> Void)
}

func jsonData(_ value: [String: Any]) -> Data {
    (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data("{}".utf8)
}
