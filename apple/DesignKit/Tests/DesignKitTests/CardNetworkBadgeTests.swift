import Testing

@testable import DesignKit

@Suite struct CardNetworkBadgeTests {
    typealias N = CardNetworkBadge.CardNetwork

    @Test(arguments: [
        ("4111 1111 1111 1111", N.visa),
        ("4", N.visa),
        ("5105-1051-0510-5100", N.mastercard),
        ("5500000000000004", N.mastercard),
        ("2221000000000009", N.mastercard),
        ("2720990000000000", N.mastercard),
        ("2220990000000000", N.unknown),
        ("2721000000000000", N.unknown),
        ("378282246310005", N.amex),
        ("341111111111111", N.amex),
        ("6011111111111117", N.discover),
        ("6500000000000002", N.discover),
        ("6440000000000000", N.discover),
        ("6490000000000000", N.discover),
        ("6430000000000000", N.unknown),
        ("3528000000000000", N.jcb),
        ("3589000000000000", N.jcb),
        ("3590000000000000", N.unknown),
        ("6200000000000005", N.unionPay),
        ("5600000000000000", N.unknown),
        ("", N.unknown),
        ("5", N.unknown),
        ("abcd", N.unknown),
    ])
    func detect(_ number: String, _ expected: N) {
        #expect(N.detect(number: number) == expected)
    }

    @Test func cbIsNeverDetected() {
        #expect(!["4970", "5132", "4000"].map { N.detect(number: $0 + "000000000000") }.contains(.cb))
    }
}
