//
//  JailbreakDetector.swift
//  jaildetect
//
//  Created by Julia Potapenko on 1/4/20.
//  Copyright © 2020 Julia Potapenko. All rights reserved.
//

import Foundation
import UIKit

import Darwin
import MachO

class JailbreakDetector {
    
    var isCompromised: Bool {
        
        #if targetEnvironment(simulator)
        return false
        #else
        return containsJailbreakTraces || respondsToMaliciousSchemes || isSandboxWriteAccessViolated || isSandboxReadAccessViolated || isSandboxProcessViolated || runningOnRoot || hasSymbolicLinks || hasMaliciousDylib || isDebuggerAttached
        #endif
        
    }
    
    var containsJailbreakTraces: Bool {
        let pathsList: [String] = ["/Applications/Cydia.app",
                                   "/Applications/RockApp.app",
                                   "/Applications/Icy.app",
                                   "/Applications/WinterBoard.app",
                                   "/Applications/SBSettings.app",
                                   "/Applications/MxTube.app",
                                   "/Applications/IntelliScreen.app",
                                   "/Applications/FakeCarrier.app",
                                   "/Applications/blackra1n.app",
                                   "/Library/MobileSubstrate/MobileSubstrate.dylib",
                                   "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
                                   "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
                                   "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
                                   "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
                                   "/bin/bash",
                                   "/bin/sh",
                                   "/usr/sbin/sshd",
                                   "/usr/sbin/frida-server",
                                   "/usr/libexec/ssh-keysign",
                                   "/usr/libexec/sftp-server",
                                   "/usr/bin/sshd",
                                   "/etc/apt",
                                   "/var/cache/apt",
                                   "/var/lib/apt",
                                   "/var/lib/cydia",
                                   "/var/log/syslog",
                                   "/var/tmp/cydia.log",
                                   "/private/var/stash",
                                   "/private/var/tmp/cydia.log",
                                   "/private/var/lib/cydia",
                                   "/private/var/mobile/Library/SBSettings/Themes",
                                   "/private/var/lib/apt"]
        for path in pathsList {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    var respondsToMaliciousSchemes: Bool {
        let schemesList: [String] = ["cydia://", "undecimus://", "sileo://"]
        for scheme in schemesList {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        return false
    }
    
    var isSandboxWriteAccessViolated: Bool {
        let pathsList = ["/", "/root/", "/private/"]
        let testString = "Test"
        for path in pathsList {
            do {
                let fullPath = path + UUID().uuidString + ".test"
                try testString.write(toFile: fullPath, atomically:true, encoding:.utf8)
                try FileManager.default.removeItem(atPath: fullPath)
                return true
            } catch { }
        }
        return false
    }
    
    var isSandboxReadAccessViolated: Bool {
        let pathsList: [String] = ["/bin/bash",
                                   "/bin/sh",
                                   "/usr/sbin/sshd",
                                   "/etc/apt",
                                    "/var/log/apt",
                                   "/Applications/Cydia.app",
                                   "/Library/MobileSubstrate/MobileSubstrate.dylib",
                                   "/.installed_unc0ver",
                                   "/.bootstrapped_electra"]
        for path in pathsList {
            if FileManager.default.isReadableFile(atPath: path) {
                return true
            }
        }
        return false
    }
    
    var isSandboxProcessViolated: Bool {
        let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointerToFork, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let pid = fork()
        return pid >= 0
    }
    
    var runningOnRoot: Bool {
        let root = getgid()
        return root <= 10
    }
    
    var hasSymbolicLinks: Bool {
        let pathsList = ["/var/lib/undecimus/apt",
                         "/Applications",
                         "/Library/Ringtones",
                         "/Library/Wallpaper",
                         "/usr/arm-apple-darwin9",
                         "/usr/include",
                         "/usr/libexec",
                         "/usr/share"]

        for path in pathsList {
            do {
                let result = try FileManager.default.destinationOfSymbolicLink(atPath: path)
                if !result.isEmpty {
                    return true
                }
            } catch { }
        }
        return false
    }
    
    var hasMaliciousDylib: Bool {
        let maliciousDylibsList: [String] = ["cycript",
                                             "cynject",
                                             "tweakinject",
                                             "sslkillswitch",
                                             "substrate",
                                             "frida"]
        for index in 0..<_dyld_image_count() {
            let appDylib = String(cString: _dyld_get_image_name(index)).lowercased()
            for maliciousDylib in maliciousDylibsList {
                if appDylib.contains(maliciousDylib) {
                    return true
                }
            }
        }
        return false
    }
    
    var isDebuggerAttached: Bool {
        var info = kinfo_proc()
        var mib : [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let res = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if res != 0 {
            return false
        }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    func disableDebugger() {
        let pointerToPtrace = UnsafeMutableRawPointer(bitPattern: -2)
        let ptracePtr = dlsym(pointerToPtrace, "ptrace")
        typealias PtraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
        let ptrace = unsafeBitCast(ptracePtr, to: PtraceType.self)
        _ = ptrace(31, 0, 0, 0)
    }
    
}
