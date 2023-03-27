//go:build unit_test
// +build unit_test

package secrets_test

import (
	"os"
	"path/filepath"
	"strings"

	"sorsops/vault-env/v2/secrets"

	"sorsops/vault-env/v2/models"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Secrets", func() {

	Describe("Validation", func() {

		It("throws an error if no version found", func() {

			dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
			if err != nil {
				Expect(err).ShouldNot(HaveOccurred())
				return
			}
			err = secrets.RetrieveSecrets(&models.SecretCtx{
				InputFile: filepath.Join(dir, "../tests/secrets/version-missing.yml"),
			})
			Expect(err).Should(MatchError("`version` must be passed"))
		})
		It("throws an error if mismatched version found", func() {

			dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
			if err != nil {
				Expect(err).ShouldNot(HaveOccurred())
				return
			}
			err = secrets.RetrieveSecrets(&models.SecretCtx{
				InputFile: filepath.Join(dir, "../tests/secrets/version-wrong.yml"),
			})
			Expect(err).Should(MatchError("Only major version `1` is supported"))
		})
	})

	Describe("Path formatting", func() {

		It("Returns the correctly formatted path when forward slash", func() {
			val := secrets.FormatPath("aws", "/aws", "/path/value")
			Expect(val).To(Equal("aws/path/value"))
		})

		It("Returns the correctly formatted path when no forward slash", func() {
			val := secrets.FormatPath("aws", "/aws", "path/value")
			Expect(val).To(Equal("aws/path/value"))
		})

		It("Returns the correctly formatted path when no root provided", func() {
			val := secrets.FormatPath("aws", "", "/aws/path/value")
			Expect(val).To(Equal("aws/path/value"))
		})
	})

	Describe("Environment support", func() {

		It("Injects the correct environment values", func() {

			name := "TEST_VAL"
			value := "rAFZDFAFEWRAGDSWCF"
			os.Setenv(name, value)
			absPath, _ := filepath.Abs("../tests/.secrets.yml")
			val, err := secrets.GetYamlConfig(absPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Contains(string(val), value)).To(Equal(true))
		})
	})
})
