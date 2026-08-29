package firewall

// Typed execution arguments shared with state wrappers. Keeping these structs
// public lets states call the registry without depending on unexported Windows
// implementation details; build-tag-specific execution code aliases them.
type ConfigArgs struct{}
type ProfileArgs struct {
	Profile string `statekit:"name=profile"`
}
type RuleExistsArgs struct {
	Name string `statekit:"required,name=name"`
}
type AddRuleArgs struct {
	Name      string  `statekit:"required"`
	LocalPort string  `statekit:"required,name=localport"`
	Protocol  *string `statekit:"name=protocol"`
	Action    *string `statekit:"name=action"`
	Dir       *string `statekit:"name=dir"`
	RemoteIP  *string `statekit:"name=remoteip"`
}
