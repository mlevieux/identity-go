package curve25519_test

import (
	"github.com/TankerHQ/identity-go/v3/curve25519"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("curve25519Generate", func() {
	It("generates a non nil key pair", func() {
		sk, pk, err := curve25519.GenerateKey()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(len(sk)).Should(Equal(32))
		Expect(len(pk)).Should(Equal(32))

		emptyArray := [32]byte{}
		Expect(sk).ShouldNot(Equal(emptyArray[:]))
		Expect(pk).ShouldNot(Equal(emptyArray[:]))
	})

	It("generates different keys each time", func() {
		sk, pk, err := curve25519.GenerateKey()
		Expect(err).ShouldNot(HaveOccurred())
		sk2, pk2, err := curve25519.GenerateKey()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(sk).ShouldNot(Equal(sk2))
		Expect(pk).ShouldNot(Equal(pk2))
	})
})
