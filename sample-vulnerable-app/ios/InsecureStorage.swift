import Foundation
import CommonCrypto

// Intentionally INSECURE sample. Demonstrates findings; do not copy.
final class InsecureStorage {

    // (1) Hardcoded secret in the binary -> SECRET_GENERIC_API / MASVS-STORAGE-1
    private let apiKey = "api_key=AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"

    // (2) Secrets in NSUserDefaults (not the Keychain) -> MASTG-TEST-0053
    func saveToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "session_token")
    }

    // (3) Weak hashing with MD5 -> CRYPTO_MD5 / MASVS-CRYPTO-1
    func fingerprint(_ data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
