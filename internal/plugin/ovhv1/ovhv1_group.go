package ovhv1

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func (p *OVHv1Group) Name() string {
	if p.plugin != nil {
		return p.plugin.Name()
	}
	return pluginName
}

func (p *OVHv1Group) Capabilities() plugin.Capabilities {
	if p.plugin != nil {
		return p.plugin.Capabilities()
	}
	return plugin.Capabilities{}
}

func (p *OVHv1Group) checkCredentials(ctx context.Context) error {
	var me ovhMe
	if err := p.getWithContext(ctx, "/me", &me); err != nil {
		return fmt.Errorf("%s: credential check failed: %w", pluginName, err)
	}
	p.logger().Info("ovh credentials ok",
		"nichandle", me.Nichandle,
	)
	return nil
}

func (p *OVHv1Group) Update(ctx context.Context, req plugin.UpdateRequest) (plugin.UpdateResult, error) {
	zone := strings.TrimSuffix(req.Zone, ".")

	// First call - find or create task
	if len(req.Raw) == 0 {
		return p.startUpdate(ctx, zone, req)
	}

	// Resume - manage existing task
	taskID, err := rawTaskID(req.Raw)
	if err != nil {
		return plugin.UpdateResult{}, err
	}

	task, err := p.getTask(ctx, zone, taskID)
	if err != nil {
		return plugin.UpdateResult{}, err
	}

	// Check if finished
	if done, result, err := finishedTaskResult(taskID, task.Status); done {
		return result, err
	}

	if task.CanAccelerate {
		if p.allowAcceleration {
			if err := p.accelerate(ctx, zone, taskID); err != nil {
				p.logger().Warn("failed to accelerate task", "task_id", taskID, "error", err)
			}
			return plugin.UpdateResult{
				InProgress: true,
				Raw:        buildRaw(taskID),
				NextWait:   p.plugin.waitPollUrgent,
			}, nil
		}

		return plugin.UpdateResult{
			InProgress: true,
			Raw:        buildRaw(taskID),
			NextWait:   p.plugin.waitPollPassive,
		}, nil
	}

	// Continue normally
	return plugin.UpdateResult{
		InProgress: true,
		Raw:        buildRaw(taskID),
		NextWait:   p.plugin.waitPollUrgent,
	}, nil
}

func (p *OVHv1Group) startUpdate(ctx context.Context, zone string, req plugin.UpdateRequest) (plugin.UpdateResult, error) {
	task, found, err := p.findRunningTask(ctx, zone)
	if err != nil {
		return plugin.UpdateResult{}, err
	}
	if found {
		return runningTaskResult(task), nil
	}

	currentKeys, err := p.loadCurrentKeys(ctx, zone)
	if err != nil {
		return plugin.UpdateResult{}, err
	}

	desired, added, removed := buildDesiredKeys(currentKeys, req)
	if added == 0 && removed == 0 {
		p.logger().Info("OVH DS already match desired set, skipping update", "zone", zone)
		return plugin.UpdateResult{}, nil
	}

	return p.submitUpdate(ctx, zone, req, desired, added, removed)
}

func (p *OVHv1Group) findRunningTask(ctx context.Context, zone string) (ovhTask, bool, error) {
	var taskIDs []int
	if err := p.getWithContext(ctx, fmt.Sprintf("/domain/%s/task", zone), &taskIDs); err != nil {
		return ovhTask{}, false, fmt.Errorf("listing tasks for %s: %w", zone, err)
	}

	for _, tid := range taskIDs {
		task, err := p.getTask(ctx, zone, strconv.Itoa(tid))
		if err != nil {
			continue
		}
		if isDNSSECTask(task.Function) && (task.Status == "todo" || task.Status == "doing") {
			return task, true, nil
		}
	}

	return ovhTask{}, false, nil
}

func (p *OVHv1Group) loadCurrentKeys(ctx context.Context, zone string) (map[int]ovhKey, error) {
	var currentKeyIDs []int
	if err := p.getWithContext(ctx, fmt.Sprintf("/domain/%s/dsRecord", zone), &currentKeyIDs); err != nil {
		return nil, fmt.Errorf("listing current DS records for %s: %w", zone, err)
	}

	currentKeys := make(map[int]ovhKey, len(currentKeyIDs))
	for _, kid := range currentKeyIDs {
		var key ovhKey
		if err := p.getWithContext(ctx, fmt.Sprintf("/domain/%s/dsRecord/%d", zone, kid), &key); err != nil {
			return nil, fmt.Errorf("reading DS record %d for %s: %w", kid, zone, err)
		}
		currentKeys[kid] = key
	}

	return currentKeys, nil
}

func (p *OVHv1Group) submitUpdate(ctx context.Context, zone string, req plugin.UpdateRequest, desired []ovhKey, added int, removed int) (plugin.UpdateResult, error) {
	p.logger().Info("submitting DS update",
		"zone", zone,
		"add_count", added,
		"remove_count", removed,
		"requested_add", len(req.ToAdd),
		"requested_remove", len(req.ToRemove),
		"desired_count", len(desired),
	)

	payload := ovhDSPayload{Keys: desired}
	var task ovhTask
	if err := p.postWithContext(ctx, fmt.Sprintf("/domain/%s/dsRecord", zone), &payload, &task); err != nil {
		return plugin.UpdateResult{}, fmt.Errorf("posting DS update for %s: %w", zone, err)
	}

	// Keep polling after submit; acceleration availability may appear asynchronously.
	return plugin.UpdateResult{
		InProgress: true,
		Raw:        buildRaw(strconv.Itoa(task.ID)),
		NextWait:   p.plugin.waitSubmit,
	}, nil
}

func (p *OVHv1Group) getTask(ctx context.Context, zone string, taskID string) (ovhTask, error) {
	var task ovhTask
	if err := p.getWithContext(ctx, fmt.Sprintf("/domain/%s/task/%s", zone, taskID), &task); err != nil {
		return ovhTask{}, fmt.Errorf("checking task %s for %s: %w", taskID, zone, err)
	}
	return task, nil
}

func (p *OVHv1Group) accelerate(ctx context.Context, zone string, taskID string) error {
	zone = strings.TrimSuffix(zone, ".")
	return p.postWithContext(ctx, fmt.Sprintf("/domain/%s/task/%s/accelerate", zone, taskID), nil, nil)
}
