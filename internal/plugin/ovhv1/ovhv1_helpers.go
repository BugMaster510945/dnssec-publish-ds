package ovhv1

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func runningTaskResult(task ovhTask) plugin.UpdateResult {
	return plugin.UpdateResult{
		InProgress: true,
		Raw:        buildRaw(strconv.Itoa(task.ID)),
	}
}

func finishedTaskResult(taskID string, status string) (bool, plugin.UpdateResult, error) {
	switch status {
	case "done":
		return true, plugin.UpdateResult{}, nil
	case "error", "problem", "cancelled":
		return true, plugin.UpdateResult{}, fmt.Errorf("task %s ended with status %q", taskID, status)
	default:
		return false, plugin.UpdateResult{}, nil
	}
}

func buildRaw(taskID string) map[string]any {
	return map[string]any{
		"task_id": taskID,
	}
}

func rawTaskID(raw map[string]any) (string, error) {
	taskID, _ := raw["task_id"].(string)
	if taskID == "" {
		return "", fmt.Errorf("missing task_id in OVH raw state")
	}
	return taskID, nil
}

func canonicalOVHKey(key ovhKey) string {
	return fmt.Sprintf("%d/%d/%d/%s", key.Tag, key.Algorithm, key.Flags, key.PublicKey)
}

func tagAlgoKey(tag uint16, algo uint8) string {
	return fmt.Sprintf("%d/%d", tag, algo)
}

func tagAlgoKeyFromOVH(key ovhKey) string {
	return fmt.Sprintf("%d/%d", key.Tag, key.Algorithm)
}

func isDNSSECTask(taskFunction string) bool {
	f := strings.ToLower(strings.TrimSpace(taskFunction))
	return strings.Contains(f, "dnssec") ||
		strings.Contains(f, "domainds") ||
		strings.Contains(f, "dsrecord")
}

func buildDesiredKeys(current map[int]ovhKey, req plugin.UpdateRequest) ([]ovhKey, int, int) {
	added := 0
	removed := 0
	desiredByCanonical := make(map[string]ovhKey, len(current))
	for _, key := range current {
		desiredByCanonical[canonicalOVHKey(key)] = key
	}

	for _, remove := range req.ToRemove {
		needle := tagAlgoKey(remove.Tag, remove.Algorithm)
		for canonical, key := range desiredByCanonical {
			if tagAlgoKeyFromOVH(key) == needle {
				removed++
				delete(desiredByCanonical, canonical)
			}
		}
	}

	for _, add := range req.ToAdd {
		if add.PublicKey == nil || add.Flags == nil {
			continue
		}
		newKey := ovhKey{
			Algorithm: int(add.Algorithm),
			Flags:     int(*add.Flags),
			PublicKey: *add.PublicKey,
			Tag:       int(add.Tag),
		}
		can := canonicalOVHKey(newKey)
		if _, exists := desiredByCanonical[can]; exists {
			// key already present — nothing to do
			continue
		}
		added++
		desiredByCanonical[can] = newKey
	}

	// Récupère la liste des id de clés et les tries
	canonicalKeys := make([]string, 0, len(desiredByCanonical))
	for canonical := range desiredByCanonical {
		canonicalKeys = append(canonicalKeys, canonical)
	}
	sort.Strings(canonicalKeys)

	// Ordonne la sortie selon les id de clés triés
	desired := make([]ovhKey, 0, len(desiredByCanonical))
	for _, canonical := range canonicalKeys {
		desired = append(desired, desiredByCanonical[canonical])
	}

	return desired, added, removed
}
