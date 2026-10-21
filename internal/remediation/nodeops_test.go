package remediation

import "testing"

func TestNodeActionsValidate(t *testing.T) {
	base := RemediationPlan{ActionType: ActionCordonNode, TargetGVK: "v1/Node", TargetName: "worker-1", Params: CordonNodeParams{Unschedulable: true}, Reversible: true, RiskLevel: RiskMedium}
	if err := base.Validate(); err != nil {
		t.Fatalf("a cordon of a Node must validate: %v", err)
	}
	wrongKind := base
	wrongKind.TargetGVK, wrongKind.TargetNamespace = "apps/v1/Deployment", "prod"
	if wrongKind.Validate() == nil {
		t.Fatal("a node action against a Deployment must be refused")
	}
	drain := RemediationPlan{ActionType: ActionDrainNode, TargetGVK: "v1/Node", TargetName: "worker-1", Params: DrainNodeParams{}, Reversible: true, RiskLevel: RiskHigh}
	if drain.Validate() == nil {
		t.Fatal("a drain claiming to be reversible must be refused")
	}
	drain.Reversible = false
	if err := drain.Validate(); err != nil {
		t.Fatalf("an honest drain must validate: %v", err)
	}
	if BaseRiskFloors()[ActionDrainNode] != RiskHigh || !neverAutoApprove[ActionDrainNode] || !neverAutoApprove[ActionCordonNode] {
		t.Fatal("drain must floor at high and neither node action may ever be auto-approved")
	}
}
