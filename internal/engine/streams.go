package engine

// RegisterStream explicitly registers a stream for a tenant.
func (e *Engine) RegisterStream(tenant, source, stream string) {
	if tenant == "" {
		tenant = LocalTenant
	}
	e.stateForWrite(tenant).registerStream(source, stream)
}

// MarkStreamInactive marks a tenant stream as inactive (e.g. file finished).
func (e *Engine) MarkStreamInactive(tenant, source, stream string) {
	if tenant == "" {
		tenant = LocalTenant
	}
	if t := e.stateFor(tenant); t != nil {
		t.markStreamInactive(source, stream)
	}
}
