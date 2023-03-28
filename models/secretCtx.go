package models

//SecretCtx : The inputs we receive from the CLI that need to be globally accessible
type SecretCtx struct {
	VaultAddress string
	InputFile    string
	Collection   string
	Output       string
	DefaultToken string
	Format       string
}
