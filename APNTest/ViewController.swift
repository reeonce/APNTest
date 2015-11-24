//
//  ViewController.swift
//  APNTest
//
//  Created by Reeonce on 11/23/15.
//  Copyright © 2015 Reeonce. All rights reserved.
//

import Cocoa
import Security
import CocoaAsyncSocket

struct Item: CustomStringConvertible {
    var itemID: UInt8
    var itemLength: Int16
    var data: NSData
    
    var description: String {
        return ""
    }
    
    func getData() -> NSData {
        var id = itemID
        var length = itemLength.bigEndian
        
        let tmpdata = NSMutableData(bytes: &id, length: 1)
        tmpdata.appendBytes(&length, length: 2)
        tmpdata.appendData(data)
        return tmpdata
    }
}

extension UInt {
    init?(_ string: String, radix: UInt) {
        let digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        var result = UInt(0)
        for digit in string.characters {
            if let range = digits.rangeOfString(String(digit)) {
                let val = UInt(digits.startIndex.distanceTo(range.startIndex))
                if val >= radix {
                    return nil
                }
                result = result * radix + val
            } else {
                return nil
            }
        }
        self = result
    }
}

extension String {
    func hexString2Data() -> NSData {
        let stringData = NSMutableData()
        
        for i in 0 ..< characters.count {
            if (i % 2 == 1) {
                continue
            }
            let charString = substringWithRange(Range<Index>(start: startIndex.advancedBy(i), end: startIndex.advancedBy(i + 2)))
            
            var hexValue = UInt(charString, radix: 16)
            
            let data = NSData(bytes: &hexValue, length: 1)
            
            stringData.appendData(data)
        }
        
        return stringData
    }
}

class ViewController: NSViewController, GCDAsyncSocketDelegate {

    var socket: GCDAsyncSocket!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let delegateQueue = dispatch_queue_create("delegate queue", DISPATCH_QUEUE_SERIAL)
        
        socket = GCDAsyncSocket(delegate: self, delegateQueue: delegateQueue)
        
        connectSocket()
    }
    
    func sendData() {
        let data = getAPNData()
        socket.writeData(data, withTimeout: 20, tag: 100)
        
        
        var command: UInt8 = 0
        var frameLength: Int32 = 0
        data!.getBytes(&command, range: NSMakeRange(0, 1))
        data!.getBytes(&frameLength, range: NSMakeRange(1, 4))
        frameLength = frameLength.byteSwapped
        
        var frameData = data?.subdataWithRange(NSMakeRange(5, Int(frameLength)))
        
        while let frameData1 = frameData where frameData1.length > 0 {
            var itemID: UInt8 = 0
            var itemLength: Int16 = 0
            frameData1.getBytes(&itemID, range: NSMakeRange(0, 1))
            frameData1.getBytes(&itemLength, range: NSMakeRange(1, 2))
            itemLength = itemLength.byteSwapped
            
            let content = frameData1.subdataWithRange(NSMakeRange(3, Int(itemLength)))
            print("itemID: \(itemID), itemLength: \(itemLength)")
            print(String(data: content, encoding: NSASCIIStringEncoding))
            
            frameData = frameData1.subdataWithRange(NSMakeRange(3 + Int(itemLength), frameData1.length - 3 - Int(itemLength)))
        }
        
    }
    
    func connectSocket() {
        do {
            try socket.connectToHost("gateway.sandbox.push.apple.com", onPort: 2195)
        } catch let e {
            print(e)
        }
    }
    
    func enableTLS() {
        let path = NSBundle.mainBundle().pathForResource("Certificates-dev-p", ofType: "p12")
        if let p12Data = NSData(contentsOfFile: path!) {
            let options = NSDictionary(dictionary: [kSecImportExportPassphrase: "turingcat"])
            var items: NSArray? = nil
            withUnsafeMutablePointer(&items, {
                let status = SecPKCS12Import(p12Data, options, UnsafeMutablePointer($0))
                let error = NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
                print(error.localizedDescription)
            })
            let firstItem = items?.firstObject as? NSDictionary
            let identity = firstItem?.objectForKey(kSecImportItemIdentity) as! SecIdentityRef
            var centificate: SecCertificateRef? = nil
            SecIdentityCopyCertificate(identity, &centificate)
            
            let settings = NSArray(objects: identity, centificate!)
            
            socket.startTLS([kCFStreamSSLCertificates: settings,
                ])
        }
    }

    func socket(sock: GCDAsyncSocket!, didReadData data: NSData!, withTag tag: Int) {
        
        var command: UInt = 0
        var status: UInt = 0
        data.getBytes(&command, range: NSMakeRange(0, 1))
        data.getBytes(&status, range: NSMakeRange(1, 1))
        print("read with tag: \(tag), command: \(command), status: \(status)")
        
        let dataString = String(data:data, encoding: NSUTF8StringEncoding)
        print(dataString)
    }
    
    func socket(sock: GCDAsyncSocket!, didWriteDataWithTag tag: Int) {
        print("write with tag \(tag)")
        socket.readDataToLength(6, withTimeout: -1, tag: 300)
    }
    
    func socket(sock: GCDAsyncSocket!, didReceiveTrust trust: SecTrust!, completionHandler: ((Bool) -> Void)!) {
        completionHandler(true)
    }
    
    func socketDidSecure(sock: GCDAsyncSocket!) {
        print("socketDidSecure")
        sendData()
    }
    
    func socket(sock: GCDAsyncSocket!, didAcceptNewSocket newSocket: GCDAsyncSocket!) {
        print("accept new socket")
    }
    
    func socket(sock: GCDAsyncSocket!, didConnectToHost host: String!, port: UInt16) {
        print("connect to host")
        enableTLS()
    }
    
    func socketDidDisconnect(sock: GCDAsyncSocket!, withError err: NSError!) {
        print("disconnect to host")
        print(err)
    }

    override var representedObject: AnyObject? {
        didSet {
        // Update the view, if already loaded.
        }
    }

    func getAPNData() -> NSData? {
        let jsonString = "{\"aps\":{\"alert\":{\"body\":\"Hello from Apple Notification Service\",\"title\":\"Optional title\"},\"category\":\"myCategory\"},\"customKey\":\"Use thiApp.\"}"
        
        guard let jsonData = jsonString.dataUsingEncoding(NSUTF8StringEncoding) else {
            exit(0)
        }
        
        let deviceToken = "529a5dd219a8b321a66388a5a951d74d47f6bbe0569ffba2fcb3a65cdbe86978".hexString2Data()
        
        let deviceTokenString = deviceToken.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)
        print(deviceTokenString)
        
        let deviceTokenItem = Item(itemID: 1, itemLength: 32, data: deviceToken)
        
        var payloadItem = Item(itemID: 2, itemLength: 32, data: jsonData)
        payloadItem.itemLength = Int16(payloadItem.data.length)
        
        var identifier: UInt = 2346
        let identifierItem = Item(itemID: 3, itemLength: 4, data: NSData(bytes: &identifier, length: 1))
        
        var expireDate = NSDate(timeIntervalSinceNow: 600).timeIntervalSince1970
        let expireDateData = NSData()
        expireDateData.getBytes(&expireDate, length: 4)
        let expireDateItem = Item(itemID: 4, itemLength: 4, data: expireDateData)
        
        var priority: UInt8 = 10
        let priorityItem = Item(itemID: 5, itemLength: 1, data: NSData(bytes: &priority, length: 1))
        
        let frameData = NSMutableData()
        frameData.appendData(deviceTokenItem.getData())
        frameData.appendData(payloadItem.getData())
        frameData.appendData(identifierItem.getData())
        frameData.appendData(expireDateItem.getData())
        frameData.appendData(priorityItem.getData())
        
        var frameLength = UInt32(frameData.length)
        frameLength = frameLength.bigEndian
        
        var command = 2
        let resultData = NSMutableData()
        resultData.appendBytes(&command, length: 1)
        resultData.appendBytes(&frameLength, length: 4)
        resultData.appendData(frameData)
        
        return resultData
    }
}

