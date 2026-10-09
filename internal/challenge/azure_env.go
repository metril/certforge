package challenge

// forceAzureEnvAuth pins lego's azuredns to the supplied client-secret
// fields. Without AZURE_AUTH_METHOD=env lego falls back to
// NewDefaultAzureCredential (the server's managed or workload identity) and
// ignores the supplied keys.
func forceAzureEnvAuth(code string, cfg map[string]string) map[string]string {
	if code != "azuredns" || cfg["AZURE_AUTH_METHOD"] != "" ||
		cfg["AZURE_CLIENT_ID"] == "" || cfg["AZURE_CLIENT_SECRET"] == "" || cfg["AZURE_TENANT_ID"] == "" {
		return cfg
	}
	out := make(map[string]string, len(cfg)+1)
	for k, v := range cfg {
		out[k] = v
	}
	out["AZURE_AUTH_METHOD"] = "env"
	return out
}
