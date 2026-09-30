package targets

// RegisterBuiltins registers every deploy target type internal/targets
// ships on its own — today, traefik. vault-kv (internal/deploy.VaultKV)
// registers itself wherever it is constructed instead, since it needs a
// *vault.Provider internal/targets does not, and must not, depend on.
func RegisterBuiltins(reg *Registry) {
	reg.Register(Traefik{})
}
