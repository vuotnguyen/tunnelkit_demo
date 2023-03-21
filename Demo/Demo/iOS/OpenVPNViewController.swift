//
//  OpenVPNViewController.swift
//  Demo
//
//  Created by Davide De Rosa on 2/11/17.
//  Copyright (c) 2022 Davide De Rosa. All rights reserved.
//
//  https://github.com/keeshux
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//

import UIKit
import TunnelKitCore
import TunnelKitManager
import TunnelKitOpenVPN

private let appGroup = "group.com.NEOvpn.demo"

private let tunnelIdentifier = "com.vpn-mobile-app.demo.NEOvpn"

class OpenVPNViewController: UIViewController {
    @IBOutlet var textUsername: UITextField!
    
    @IBOutlet var textPassword: UITextField!
    
    @IBOutlet var textServer: UITextField!
    
    @IBOutlet var textDomain: UITextField!
    
    @IBOutlet var textPort: UITextField!
    
    @IBOutlet var switchTCP: UISwitch!
    
    @IBOutlet var buttonConnection: UIButton!

    @IBOutlet var textLog: UITextView!

    private let vpn = NetworkExtensionVPN()
    
    private var vpnStatus: VPNStatus = .disconnected

    private let keychain = Keychain(group: appGroup)
    
    private var cfg: OpenVPN.ProviderConfiguration?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        textServer.text = "103.159.50.156"
        textDomain.text = ""
        textPort.text = "1004"
        switchTCP.isOn = false
        textUsername.text = ""
        textPassword.text = ""
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(VPNStatusDidChange(notification:)),
            name: VPNNotification.didChangeStatus,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(VPNDidFail(notification:)),
            name: VPNNotification.didFail,
            object: nil
        )

        Task {
            await vpn.prepare()
        }

//        testFetchRef()
    }
    
    @IBAction func connectionClicked(_ sender: Any) {
        switch vpnStatus {
        case .disconnected:
            connect()
            
        case .connected, .connecting, .disconnecting:
            disconnect()
        }
    }
    
    @IBAction func tcpClicked(_ sender: Any) {
    }
    
    func connect() {
        let server = textServer.text!
        let domain = textDomain.text!
        let hostname = ((domain == "") ? server : [server, domain].joined(separator: "."))
        let port = UInt16(textPort.text!)!
        let socketType: SocketType = switchTCP.isOn ? .tcp : .udp

//        let credentials = OpenVPN.Credentials(textUsername.text!, textPassword.text!)
        cfg = OpenVPN.DemoConfiguration.make(
            "TunnelKit.OpenVPN",
            appGroup: appGroup,
            hostname: hostname,
            port: port,
            socketType: socketType
        )
//        cfg?.username = credentials.username

//        let passwordReference: Data
//        do {
//            passwordReference = try keychain.set(password: credentials.password, for: credentials.username, context: tunnelIdentifier)
//        } catch {
//            print("Keychain failure: \(error)")
//            return
//        }

        Task {
//            let extra = NetworkExtensionExtra()
//            extra.passwordReference = passwordReference
            try await vpn.reconnect(
                tunnelIdentifier,
                configuration: cfg!,
                extra: nil,
                after: .seconds(2)
            )
        }
    }
    
    func disconnect() {
        Task {
            await vpn.disconnect()
        }
    }

    @IBAction func displayLog() {
        
        guard let cfg = cfg else {
            return
        }
        print("errror %@" + (cfg.lastError?.rawValue ?? "null"))
        guard let url = cfg.urlForDebugLog else {
            return
        }
       
        textLog.text = try? String(contentsOf: url)
    }
    
    func updateButton() {
        switch vpnStatus {
        case .connected, .connecting:
            buttonConnection.setTitle("Disconnect", for: .normal)
            
        case .disconnected:
            buttonConnection.setTitle("Connect", for: .normal)
            
        case .disconnecting:
            buttonConnection.setTitle("Disconnecting", for: .normal)
        }
    }
    
    @objc private func VPNStatusDidChange(notification: Notification) {
        vpnStatus = notification.vpnStatus
        print("VPNStatusDidChange: \(vpnStatus)")
        updateButton()
    }

    @objc private func VPNDidFail(notification: Notification) {
        print("VPNStatusDidFail: \(notification.vpnError.localizedDescription)")
    }

//    private func testFetchRef() {
//        let keychain = Keychain(group: appGroup)
//        let username = "foo"
//        let password = "bar"
//        
//        guard let ref = try? keychain.set(password: password, for: username, context: tunnelIdentifier) else {
//            print("Couldn't set password")
//            return
//        }
//        guard let fetchedPassword = try? Keychain.password(forReference: ref) else {
//            print("Couldn't fetch password")
//            return
//        }
//
//        print("\(username) -> \(password)")
//        print("\(username) -> \(fetchedPassword)")
//    }
}
