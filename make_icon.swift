// 生成应用图标：swift make_icon.swift <输出目录>，产出 AppIcon.icns 与 1024px 预览 PNG。
// 图形：深蓝渐变圆角方块（macOS 图标网格），白色地球表示出口网络，琥珀色定位针表示固定的静态出口。
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
let canvas: CGFloat = 1024

func symbol(_ name: String, size: CGFloat, colors: [NSColor], weight: NSFont.Weight = .semibold) -> NSImage {
    let config = NSImage.SymbolConfiguration(pointSize: size, weight: weight)
        .applying(NSImage.SymbolConfiguration(paletteColors: colors))
    return NSImage(systemSymbolName: name, accessibilityDescription: nil)!.withSymbolConfiguration(config)!
}

func draw(_ image: NSImage, centeredAt center: CGPoint, height: CGFloat) {
    let scale = height / image.size.height
    let size = CGSize(width: image.size.width * scale, height: height)
    image.draw(in: CGRect(x: center.x - size.width / 2, y: center.y - size.height / 2, width: size.width, height: size.height))
}

func render(_ pixels: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = CGSize(width: canvas, height: canvas)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    // macOS 图标网格：824pt 圆角方块居中，留出投影空间。
    let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = NSBezierPath(roundedRect: tile, xRadius: 185, yRadius: 185)
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
    shadow.shadowOffset = CGSize(width: 0, height: -12)
    shadow.shadowBlurRadius = 28
    shadow.set()
    NSColor(calibratedRed: 0.10, green: 0.20, blue: 0.48, alpha: 1).setFill()
    shape.fill()
    NSGraphicsContext.restoreGraphicsState()
    NSGradient(colors: [NSColor(calibratedRed: 0.20, green: 0.55, blue: 0.98, alpha: 1),
                        NSColor(calibratedRed: 0.09, green: 0.22, blue: 0.62, alpha: 1)])!
        .draw(in: shape, angle: -90)
    // 顶部柔光，增加层次。
    NSGradient(colors: [NSColor.white.withAlphaComponent(0.22), NSColor.white.withAlphaComponent(0)])!
        .draw(in: shape, angle: -90)
    draw(symbol("globe", size: 420, colors: [.white]), centeredAt: CGPoint(x: 492, y: 530), height: 470)
    // 定位针：琥珀色圆形底座 + 白色针，压在地球右下方。
    let badgeCenter = CGPoint(x: 700, y: 320)
    NSColor(calibratedRed: 0.09, green: 0.22, blue: 0.62, alpha: 1).setFill()
    NSBezierPath(ovalIn: CGRect(x: badgeCenter.x - 150, y: badgeCenter.y - 150, width: 300, height: 300)).fill()
    NSColor(calibratedRed: 1.0, green: 0.70, blue: 0.16, alpha: 1).setFill()
    NSBezierPath(ovalIn: CGRect(x: badgeCenter.x - 128, y: badgeCenter.y - 128, width: 256, height: 256)).fill()
    draw(symbol("mappin", size: 200, colors: [.white], weight: .black), centeredAt: CGPoint(x: badgeCenter.x, y: badgeCenter.y + 4), height: 190)
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let iconset = output.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try render(base).write(to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
    try render(base * 2).write(to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
try render(1024).write(to: output.appendingPathComponent("AppIcon-preview.png"))
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", output.appendingPathComponent("AppIcon.icns").path]
try iconutil.run(); iconutil.waitUntilExit()
try FileManager.default.removeItem(at: iconset)
guard iconutil.terminationStatus == 0 else { fatalError("iconutil 生成失败") }
