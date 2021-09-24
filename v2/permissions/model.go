package permissions

// EntityIDToPolicies maps an entity ID to a slice of policies.
type EntityIDToPolicies map[string][]Policy

// PermissionToEntityLookup maps a permission ID to the next level in the lookup table - the EntityIDToPolicies map.
type PermissionToEntityLookup map[string]EntityIDToPolicies

// Bundle is the optimised lookup table for permissions.
type Bundle struct {
	PermissionToEntityLookup
}

// Policy is the policy model as stored in the permissions API.
type Policy struct {
	PolicyID   string      `json:"policy_id"`
	Conditions []Condition `json:"conditions"`
}

// Condition is used within a policy to match additional attributes.
type Condition struct {
	Attributes []string `json:"attributes"`
	Operator   string   `json:"operator"`
	Values     []string `json:"values"`
}

// EntityData groups the different entity types into a single parameter
type EntityData struct {
	UserID    string
	ServiceID string
	Groups    []string
}
