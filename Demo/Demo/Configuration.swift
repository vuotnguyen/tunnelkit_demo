//
//  Configuration.swift
//  Demo
//
//  Created by Davide De Rosa on 6/13/20.
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

import Foundation
import TunnelKitCore
import TunnelKitOpenVPN
import TunnelKitWireGuard

extension OpenVPN {
    struct DemoConfiguration {
        static let ca = OpenVPN.CryptoContainer(pem: """
-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUEQatR35KKwEkq97wmzkpgio4vZYwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMjIwNzI4MDk0OTMyWhcNMzIw
NzI1MDk0OTMyWjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJZtzCfeI3XnfqOrjvLMYr74nv8WyRbZFUuhNrCZ
irqbel09HwW5SQ7Y7262a6o8Jx344K6qdSi9PDqZGOWkEtYmDn9hIS95MbiDSVNr
h9xaLtrP8eQWAeaQ/td04GhYB8XK9xfx2Ytixya4j20kvwS4nyKr2EskKfni2PCB
BaWTcBO6pLwsgUSoMteeR9T0kS62cu3bC2kiZl8DnKZx31HByDzZbfjTNOja2864
TEgi+9gWoPeqQMsiv3tKzvx592OiqPGqTgMZ/JLj94ZxoMIgxgJew1yvfImU7/d1
Lr3Csz0iUlyXybkSt68cSz3iXKf7ZOBpNQ+DD+wubfWU1X0CAwEAAaOBkDCBjTAd
BgNVHQ4EFgQU0nYPL7B3EQGvGEvf/XTzkh/ceo0wUQYDVR0jBEowSIAU0nYPL7B3
EQGvGEvf/XTzkh/ceo2hGqQYMBYxFDASBgNVBAMMC0Vhc3ktUlNBIENBghQRBq1H
fkorASSr3vCbOSmCKji9ljAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkq
hkiG9w0BAQsFAAOCAQEAX3FXzEmp2L2tAqU8pFjIScA42+jnmvMZIifYvKiY6Izy
Z56G2xec03K9zlpnff8w9qYKnXNkwSyEwlZtBmJvkkGpf2gJy7SLWh0/BglbMEqb
FlC8XVtdomuX5KOVuk05kRuRWyg19/N4AA/81t1aovwTwC+odOdvG30n7ZEhmyau
521cJ2DXwqOQ/w9JMoNPdudToS2XZeVlNP3udoZ/wM6J1tgAbSHPRZTY6IZiQkI+
G7GlDAp8qVLdsqQSLaeu+H12EI5X+3q2Tk+JmNx6q51MeyamyoF3Eh76TlvRdnKW
EqEcEGmlrMJa9/YBr41mEtGOK4MDRvj/VLb5Gk6XtA==
-----END CERTIFICATE-----
""")
        
        static let clientCer = OpenVPN.CryptoContainer(pem: """
-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIQSUz0IhvHm8M+yR6JvquiFDANBgkqhkiG9w0BAQsFADAW
MRQwEgYDVQQDDAtFYXN5LVJTQSBDQTAeFw0yMzAzMDQxNjA2NTZaFw0yNTA2MDYx
NjA2NTZaMB0xGzAZBgNVBAMMEjIzMDMwNDIzMDQxMjAwMDAwMTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMmjcP7EiLsexTjzabwfbzpzghRXe52ojukv
y6KE8qePhLxQCNAkXZVPnCpvSLJiLG2wyKug/g84AY3UJKtxoF9Bm2RTyIEeq/mr
M/y4dSkXRubbwNTrGB1mVE69WxUpc4FKskk8xj6Bg+/xaD9njzfRxwLGeWt+KMF3
abIS0wg2w2SLjCVRvcfqMU5q9zOZLDFcOp6NiH0ToiIfyhFLU12TzfrKDaZ/rL5B
JgaFP0/wpUXPV0B2MBxmX4oBRDRUOw7T92Ocfbvwgrm6BTh11lQuCk2bYSB7CWrE
GCugd37/8ExSzYevTLKkskBapF2I8z5+2obpFYVu93JSfBzntEcCAwEAAaOBojCB
nzAJBgNVHRMEAjAAMB0GA1UdDgQWBBTSXihddDHLjp4BNXo7PK7d5QLduDBRBgNV
HSMESjBIgBTSdg8vsHcRAa8YS9/9dPOSH9x6jaEapBgwFjEUMBIGA1UEAwwLRWFz
eS1SU0EgQ0GCFBEGrUd+SisBJKve8Js5KYIqOL2WMBMGA1UdJQQMMAoGCCsGAQUF
BwMCMAsGA1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAIciDF4C6ZiIWKpQg
KNpMF+/V88WSEukKOG1oijt84e32HQxldLPP5QhImxE6qwDrVl4t0XzwG6ELRm6D
5CLskF/pJ4n+Cnc9LPbkZ7YME6v4Wmm27Dph8LuCjIfYSrvxwsYqc2Bqb2iYJ6dH
Usk3l9rdHeSYCYossOzG47G+m6Mt6kRJZPaSjKuPp1kr6slzLYSQcfEz6qhfPaEp
Fy1nivUfF8727+JtWhqBrQ/1QN3jiyC5DpvYaxBCe0RFahY5fc4Me9TB0/X4Nofh
FoEVI8hh4P5jIv3387BTglkLckY+y4u7WVLQmgfx9pDz1DfsmqUVbDorExRxc0OA
bKN/rQ==
-----END CERTIFICATE-----
""")
        
        static let clientKey = OpenVPN.CryptoContainer(pem: """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJo3D+xIi7HsU4
82m8H286c4IUV3udqI7pL8uihPKnj4S8UAjQJF2VT5wqb0iyYixtsMiroP4POAGN
1CSrcaBfQZtkU8iBHqv5qzP8uHUpF0bm28DU6xgdZlROvVsVKXOBSrJJPMY+gYPv
8Wg/Z4830ccCxnlrfijBd2myEtMINsNki4wlUb3H6jFOavczmSwxXDqejYh9E6Ii
H8oRS1Ndk836yg2mf6y+QSYGhT9P8KVFz1dAdjAcZl+KAUQ0VDsO0/djnH278IK5
ugU4ddZULgpNm2EgewlqxBgroHd+//BMUs2Hr0yypLJAWqRdiPM+ftqG6RWFbvdy
Unwc57RHAgMBAAECggEAf5HXMGg5NWGvV2uw7qNYpLtlhecfP0zgNanWhNjmCJrl
WJquKLmJN6jpXXOQo8M25qMdInC1q/08BnY8SPeXhgyk+mGDjiVQmqH1PyOYhEnE
wtQveMXQOPF/z10/nfDeseMHTwyTRAJ+7bRmxw6G7sLazOey9A4aTOR2y4HbX+re
QMuGp/ZX9dyNjNFny4wdkefVh4wGA7sYluYKQXzgYAUDubFPGZefRiRQ+ZA/U8Y3
GpFIXA0kkHXJpMrL2bcGRJkzgE/ku5Chp5lJqnu+UYTHr6yfLl+jA3gJCV1VIaiv
lgxUjrtLT4fNNG6U0M3NzgKe6fXkwqQfH/Xb6j88wQKBgQDoEbahYE6xZT/KJwBX
YR6rSledz8qmEu1lC8y05N5QXDKQtd4npEcZZ3UA/auYVLgEteexL3qUxY0gdrZM
cfA0XJJ18TZFqAI8rz9KJ69v7JyD3ZbuS+X8/p4p2sUJur/pGadoKDzw6q+yDxbh
r8mM+JOyaYT3Ggn9eC6eA6fE4QKBgQDebmaZqAfCf2v6vUBzbIfxqUxlo5aGka6U
v4x6F+oVO3ISXEjL5HtQJZw7eOdtc0AEuJP23aKgfBuM3c8z0Y+7uCr4ItlGTOKj
3MKNplE4s6CoI71akN8Bsn8YZYapED/MVCo6eWj5N7JW+z+EbAzxhUHBlsbSK9gm
q+aoU7l2JwKBgHggUy0NsS5afr6hmaehekKoZNonqXp16bSYewpYPkvSrcoCmlBi
1Prtdr9gj+Z2VBr8Hka1kPpZmEfpq0u+3tv730R16+X6pc3L2TMFf+ar0AjiNzJ6
zz46fpyjxcLXjGeZA/MCgSkkEnZVIT8Jw4bZVXrQ7CcMr4cpIthghAOBAoGBAL0B
4QtGnjlm31F0SXULT0VJkBJ5/Kmi10+sqOkCszWRivARHQaswyAqpWRf63+0xDx+
v7SxRsTKUPrVbIFi3Jkt+M1bh3dWU+vb5jJJlpDxCl516CwyGF2v2JHZi6DTnvK4
vh1sF4hWDKQe4S1cR29fxa2DurTS7tyFi/2TD3BXAoGAe3VKsCunEiyWkWuytV6z
71lYJVJQeWQWVRffqV7Qp8xNOG8TrjDD2bqA43KA7tm+ytaHyUeHKrVtGP5hr8BU
leKZSDsEZFI7eDxqm9J/ZLtV8jJuoo02gEp2xS9L2YZ9ghHbn6EWQk9fkg7crMG7
JiEUbyfmhXDAcoRkBR3Lti8=
-----END PRIVATE KEY-----
""")

        static let tlsKey = OpenVPN.StaticKey(file: """
-----BEGIN OpenVPN Static key V1-----
468d628dafb37c4adf4ce8dcd103e5b0
2a944563421bebb1c4360d5b3c144900
6eec8f3bb4d8349ae554a024e99de8b7
3c91f3fe13aad6ced330553ad1f5571d
618d1cd51ac56da633fa03ddcf7fc7e4
f39b0546c17df43a92b7bc0a4e1b7f74
05eaa22ce5cccee2ae3be501c4b725eb
f77317b7280b924a8cc382d4a9fba500
a7e890be84fb9d921d6e37ebd716373b
18fa1191150e859cd3748b99baf7659c
72b1309279ef15837fbd59df5db144fa
376a63a6770161a1c7d8ec7809ac973d
71b9d1d364e46e361a8f903bf637d260
0a47d1bc0aae8d28b8e87d00d7bc0ec6
33744cb1c8d6b044c7fb196fc77b986b
b3cd31b62684b583e784c227e482fee6
-----END OpenVPN Static key V1-----
""", direction: .client)!

        static func make(_ title: String, appGroup: String, hostname: String, port: UInt16, socketType: SocketType) -> OpenVPN.ProviderConfiguration {
            var builder = OpenVPN.ConfigurationBuilder()
            builder.ca = ca
            builder.clientCertificate = clientCer
            builder.clientKey = clientKey
            builder.cipher = .aes256cbc
            builder.digest = .sha512
            builder.remotes = [Endpoint(hostname, EndpointProtocol(socketType, port))]
            builder.tlsWrap = TLSWrap(strategy: .auth, key: tlsKey)
            
            builder.compressionFraming = .disabled
            builder.renegotiatesAfter = nil
//            builder.mtu = 1350
            builder.routingPolicies = [.IPv4]
            let cfg = builder.build()
            
            print("remotea.   ", builder)

            var providerConfiguration = OpenVPN.ProviderConfiguration(title, appGroup: appGroup, configuration: cfg)
            providerConfiguration.shouldDebug = true
            providerConfiguration.masksPrivateData = false
            return providerConfiguration
        }
    }
}

extension WireGuard {
    struct DemoConfiguration {
        static func make(
            _ title: String,
            appGroup: String,
            clientPrivateKey: String,
            clientAddress: String,
            serverPublicKey: String,
            serverAddress: String,
            serverPort: String
        ) -> WireGuard.ProviderConfiguration? {
            var builder = try! WireGuard.ConfigurationBuilder(clientPrivateKey)
            builder.addresses = [clientAddress]
            builder.dnsServers = ["1.1.1.1", "1.0.0.1"]
            try! builder.addPeer(serverPublicKey, endpoint: "\(serverAddress):\(serverPort)")
            builder.addDefaultGatewayIPv4(toPeer: 0)
            let cfg = builder.build()

            return WireGuard.ProviderConfiguration(title, appGroup: appGroup, configuration: cfg)
        }
    }
}
