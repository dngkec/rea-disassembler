import AppKit

// ReaDisassembler — native macOS front end for the readis engine.
// The app is a client of the engine's stable JSON CLI: it opens a binary,
// lists its functions, and shows disassembly / decompilation / strings /
// CFG per selection, with assemble-patch and LLDB debug actions.  All
// analysis stays in the engine; this file owns only the window.

struct FnItem: Decodable {
    var name: String
    var addr: String
    var end: String
    var size: Int
    var source: String
    var blocks: Int
}

struct StrItem: Decodable {
    var addr: String
    var value: String
    var encoding: String
}

struct InfoDoc: Decodable {
    var file: String
    var format: String
    var arch: String
    var bits: Int
    var entry: String
    var functions: [FnItem]
    var strings: [StrItem]
    struct Counts: Decodable {
        var functions: Int
        var instructions: Int
        var strings: Int
        var code_coverage: Double
    }
    var counts: Counts
}

final class Engine {
    var root: String
    init() {
        if let env = ProcessInfo.processInfo.environment["REA_DISASSEMBLER_HOME"] {
            root = env
        } else {
            root = NSHomeDirectory() + "/Documents/Personal/Projects/rea-disassembler"
        }
    }
    func run(_ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: root + "/.venv/bin/python")
        p.arguments = ["-m", "rea_disassembler"] + args
        p.currentDirectoryURL = URL(fileURLWithPath: root)
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = root + "/src"
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
        } catch {
            return "failed to launch engine: \(error)"
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSTableViewDataSource,
                         NSTableViewDelegate, NSSearchFieldDelegate {
    var window: NSWindow!
    var engine = Engine()
    var table: NSTableView!
    var detail: NSTextView!
    var header: NSTextField!
    var doc: InfoDoc?
    var path: String = ""
    var filter: String = ""
    var patchButton: NSButton?
    var debugButton: NSButton?

    var shownFunctions: [FnItem] {
        guard let d = doc else { return [] }
        if filter.isEmpty { return d.functions }
        return d.functions.filter { $0.name.localizedCaseInsensitiveContains(filter) }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(
            contentRect: NSRect(x: 80, y: 80, width: 1120, height: 720),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered, defer: false)
        window.title = "ReaDisassembler"
        window.minSize = NSSize(width: 800, height: 500)

        let toolbar = NSStackView()
        toolbar.orientation = .horizontal
        toolbar.spacing = 8
        let openBtn = NSButton(title: "Open Binary…", target: self, action: #selector(openFile))
        openBtn.keyEquivalent = "o"
        openBtn.keyEquivalentModifierMask = .command
        patchButton = NSButton(title: "Assemble + Patch…", target: self, action: #selector(patch))
        debugButton = NSButton(title: "Debug (LLDB)…", target: self, action: #selector(debug))
        patchButton?.isEnabled = false
        debugButton?.isEnabled = false
        let search = NSSearchField()
        search.placeholderString = "Filter functions"
        search.delegate = self
        search.widthAnchor.constraint(greaterThanOrEqualToConstant: 180).isActive = true
        header = NSTextField(labelWithString: "Open a binary to begin.")
        header.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        toolbar.addArrangedSubview(openBtn)
        if let b = patchButton { toolbar.addArrangedSubview(b) }
        if let b = debugButton { toolbar.addArrangedSubview(b) }
        toolbar.addArrangedSubview(search)
        toolbar.addArrangedSubview(header)

        table = NSTableView()
        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("fn"))
        col.title = "Functions"
        col.width = 300
        table.addTableColumn(col)
        table.headerView = nil
        table.dataSource = self
        table.delegate = self
        table.rowHeight = 18
        let listScroll = NSScrollView()
        listScroll.documentView = table
        listScroll.hasVerticalScroller = true
        listScroll.widthAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true

        let tabs = NSTabView()
        detail = NSTextView()
        detail.isEditable = false
        detail.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        let dScroll = NSScrollView()
        dScroll.documentView = detail
        dScroll.hasVerticalScroller = true
        let dItem = NSTabViewItem(identifier: "detail")
        dItem.label = "Analysis"
        dItem.view = dScroll
        tabs.addTabViewItem(dItem)

        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.addArrangedSubview(listScroll)
        split.addArrangedSubview(tabs)
        split.setHoldingPriority(.init(260), forSubviewAt: 0)
        split.setHoldingPriority(.defaultLow, forSubviewAt: 1)

        // Constraint-pinned layout: an NSStackView root does not resize an
        // NSSplitView correctly (the detail pane collapses to a sliver).
        let root = NSView()
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        split.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(toolbar)
        root.addSubview(split)
        NSLayoutConstraint.activate([
            toolbar.topAnchor.constraint(equalTo: root.topAnchor, constant: 8),
            toolbar.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 8),
            toolbar.trailingAnchor.constraint(lessThanOrEqualTo: root.trailingAnchor, constant: -8),
            split.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 6),
            split.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            split.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            split.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            listScroll.widthAnchor.constraint(greaterThanOrEqualToConstant: 260),
        ])
        window.contentView = root
        window.makeKeyAndOrderFront(nil)
        split.setPosition(330, ofDividerAt: 0)
        NSApp.activate(ignoringOtherApps: true)
        if CommandLine.arguments.count > 1 {
            load(path: CommandLine.arguments[1])
        }
    }

    func controlTextDidChange(_ obj: Notification) {
        if let f = obj.object as? NSSearchField {
            filter = f.stringValue
            table.reloadData()
        }
    }

    @objc func openFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            load(path: url.path)
        }
    }

    func load(path: String) {
        self.path = path
        header.stringValue = "Analysing \(URL(fileURLWithPath: path).lastPathComponent)…"
        DispatchQueue.global().async {
            let out = self.engine.run(["info", path, "--json"])
            let data = Data(out.utf8)
            let decoded = try? JSONDecoder().decode(InfoDoc.self, from: data)
            DispatchQueue.main.async {
                self.doc = decoded
                self.patchButton?.isEnabled = decoded != nil
                self.debugButton?.isEnabled = decoded != nil
                if let d = decoded {
                    self.header.stringValue =
                        "\(d.format) \(d.arch) \(d.bits)-bit  entry \(d.entry)  " +
                        "functions \(d.counts.functions)  instructions \(d.counts.instructions)  " +
                        "strings \(d.counts.strings)  coverage \(String(format: "%.0f%%", d.counts.code_coverage * 100))"
                    self.detail.string = self.stringsText()
                } else {
                    self.header.stringValue = "Engine error"
                    self.detail.string = out
                }
                self.table.reloadData()
            }
        }
    }

    func stringsText() -> String {
        guard let d = doc else { return "" }
        return d.strings.map { "\($0.addr)  [\($0.encoding)] \($0.value)" }
            .joined(separator: "\n")
    }

    func numberOfRows(in tableView: NSTableView) -> Int { shownFunctions.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?,
                   row: Int) -> NSView? {
        let f = shownFunctions[row]
        let cell = NSTextField(labelWithString: "\(f.addr)  \(f.name)")
        cell.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        cell.lineBreakMode = .byTruncatingTail
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = table.selectedRow
        guard row >= 0, row < shownFunctions.count, !path.isEmpty else { return }
        let f = shownFunctions[row]
        detail.string = "Loading \(f.name)…"
        DispatchQueue.global().async {
            let dis = self.engine.run(["disasm", self.path, "--function", f.addr])
            let dec = self.engine.run(["decompile", self.path, f.addr])
            let cfg = self.engine.run(["cfg", self.path, f.addr])
            DispatchQueue.main.async {
                self.detail.string =
                    "=== DISASSEMBLY  \(f.name)  \(f.addr)..\(f.end) ===\n" + dis +
                    "\n=== DECOMPILED ===\n" + dec +
                    "\n=== CFG ===\n" + cfg
            }
        }
    }

    @objc func patch() {
        guard !path.isEmpty else { return }
        let alert = NSAlert()
        alert.messageText = "Assemble and patch"
        alert.informativeText = "Instruction at the selected function address is replaced in a patched copy (original untouched, ad-hoc re-signed)."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.stringValue = "nop"
        alert.accessoryView = field
        alert.addButton(withTitle: "Patch")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let row = max(table.selectedRow, 0)
        let f = shownFunctions.indices.contains(row) ? shownFunctions[row] : shownFunctions.first
        guard let fn = f else { return }
        let out = path + ".patched"
        DispatchQueue.global().async {
            let res = self.engine.run(["patch", self.path, fn.addr, field.stringValue, "-o", out])
            DispatchQueue.main.async { self.detail.string = res }
        }
    }

    @objc func debug() {
        guard !path.isEmpty else { return }
        let row = max(table.selectedRow, 0)
        let f = shownFunctions.indices.contains(row) ? shownFunctions[row] : shownFunctions.first
        let bp = f?.name ?? "main"
        detail.string = "Running under LLDB, breakpoint: \(bp)…"
        DispatchQueue.global().async {
            let res = self.engine.run(["debug", self.path, "--break", bp])
            DispatchQueue.main.async { self.detail.string = res }
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
