// Package permissions provides library functions to determine if a user/service has a particular permission.
//
// A user can be identified by the user ID, or the groups that it belongs to. A service 'user' is identified by a service ID.
// Users, groups and services are treated the same for permissions purposes, so have the common name Entities.
//
// Entities are associated with permissions/roles via policies. For an entity to have a permission, there must be at
// least one policy that applies to that entity and permission. Policies can also have conditions that need to be met
// for the policy to apply. A policy with no conditions is equivalent to a policy where all conditions are met.
package permissions

import (
	"context"
	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"github.com/ONSdigital/dp-rchttp"
	"github.com/ONSdigital/log.go/v2/log"
	"time"
)

// Checker reads permission data and verifies that a user has a permission
type Checker struct {
	cache Cache
}

// NewCheckerForStore creates a new Checker instance.
func NewCheckerForStore(cache Cache) *Checker {
	return &Checker{
		cache: cache,
	}
}

// NewChecker creates a new Checker instance that uses the permissions API client, wrapped in a CachingStore
func NewChecker(
	ctx context.Context,
	permissionsAPIHost string,
	cacheUpdateInterval, expiryCheckInterval, maxCacheTime time.Duration) *Checker {

	apiClient := NewAPIClient(permissionsAPIHost, rchttp.NewClient())
	cachingStore := NewCachingStore(apiClient)
	cachingStore.StartCacheUpdater(ctx, cacheUpdateInterval)
	cachingStore.StartExpiryChecker(ctx, expiryCheckInterval, maxCacheTime)

	return NewCheckerForStore(cachingStore)
}

// HasPermission returns true if one of the given entities has the given permission.
//    entityData - ID of the caller (user or service), as well as any associated groups
//    permission - the action or permission the user wants to take, e.g. `datasets:edit`
//    attributes - other key value attributes for use in access control decision, e.g. `collectionID`, `datasetID`, `isPublished`, `roleId`, etc
func (c Checker) HasPermission(
	ctx context.Context,
	entityData EntityData,
	permission string,
	attributes map[string]string) (bool, error) {

	entities := mapEntityDataToEntities(entityData)
	return c.hasPermission(ctx, entities, permission, attributes)
}

// Close resources used by the checker.
func (c Checker) Close(ctx context.Context) error {
	return c.cache.Close(ctx)
}

func (c Checker) HealthCheck(ctx context.Context, state *health.CheckState) error {
	return c.cache.HealthCheck(ctx, state)
}

func mapEntityDataToEntities(entityData EntityData) []string {
	var entities []string

	if len(entityData.UserID) > 0 {
		entities = append(entities, "users/"+entityData.UserID)
	}
	if len(entityData.ServiceID) > 0 {
		entities = append(entities, "services/"+entityData.ServiceID)
	}
	for _, group := range entityData.Groups {
		if len(group) > 0 {
			entities = append(entities, "groups/"+group)
		}
	}

	return entities
}

func (c Checker) hasPermission(
	ctx context.Context,
	entities []string,
	permission string,
	attributes map[string]string) (bool, error) {

	logData := &log.Data{"permission": permission}
	permissionsBundle, err := c.cache.GetPermissionsBundle(ctx)
	if err != nil {
		return false, err
	}

	entityLookup, ok := permissionsBundle[permission]
	if !ok {
		log.Warn(ctx, "permission not found in permissions bundle", logData)
		return false, nil
	}

	for _, entity := range entities {
		policies, ok := entityLookup[entity]
		if !ok {
			continue
		}

		if aPolicyApplies(policies, attributes) {
			return true, nil
		}
	}

	return false, nil
}

func aPolicyApplies(policies []Policy, attributes map[string]string) bool {
	if policies == nil || len(policies) == 0 {
		return false
	}

	for _, policy := range policies {
		if aConditionIsMet(policy.Conditions, attributes) {
			return true
		}
	}

	return false
}

func aConditionIsMet(conditions []Condition, attributes map[string]string) bool {
	if conditions == nil || len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if conditionIsMet(condition, attributes) {
			return true
		}
	}

	return false
}

func conditionIsMet(condition Condition, attributes map[string]string) bool {
	for _, attribute := range condition.Attributes {
		value, ok := attributes[attribute]
		if !ok {
			continue
		}

		for _, conditionValue := range condition.Values {
			if condition.Operator == "=" && value == conditionValue {
				return true
			}
		}
	}

	return false
}
