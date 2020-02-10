//
//  ViewController.swift
//  jaildetect
//
//  Created by Julia Potapenko on 1/4/20.
//  Copyright © 2020 Julia Potapenko. All rights reserved.
//

import UIKit

class ViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    @IBOutlet weak var tableView: UITableView!
    
    let jaildetect = JailbreakDetector()

    var data: [(String, Bool)] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        self.updateChecks()
        self.tableView.reloadData()
    }

    func updateChecks() {
        data = [("containsJailbreakTraces", jaildetect.containsJailbreakTraces),
                ("respondsToMaliciousSchemes", jaildetect.respondsToMaliciousSchemes),
                ("isSandboxWriteAccessViolated", jaildetect.isSandboxWriteAccessViolated),
                ("isSandboxReadAccessViolated", jaildetect.isSandboxReadAccessViolated),
                ("isSandboxProcessViolated", jaildetect.isSandboxProcessViolated),
                ("runningOnRoot", jaildetect.runningOnRoot),
                ("hasSymbolicLinks", jaildetect.hasSymbolicLinks),
                ("hasMaliciousDylib", jaildetect.hasMaliciousDylib),
                ("isDebuggerAttached", jaildetect.isDebuggerAttached)]
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return self.data.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "BasicCell", for: indexPath)
        cell.textLabel?.text = data[indexPath.row].0
        cell.backgroundColor = data[indexPath.row].1 ? UIColor.red : UIColor.green
        return cell
    }

}

