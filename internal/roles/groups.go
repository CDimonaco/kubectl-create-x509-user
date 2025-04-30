package roles

import (
	"context"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1Types "k8s.io/client-go/kubernetes/typed/rbac/v1"
)

func GroupExistsInClusterRoleBindings(
	ctx context.Context,
	client rbacv1Types.RbacV1Interface,
	group string,
) (bool, error) {
	crbs, err := client.ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf(
			"could not check if the group %s exists in the clusterrolebindings, error: %w",
			group,
			err,
		)
	}

	return slices.ContainsFunc(crbs.Items, func(crb rbacv1.ClusterRoleBinding) bool {
		return slices.ContainsFunc(crb.Subjects, func(subject rbacv1.Subject) bool {
			return subject.Kind == "Group" && subject.Name == group
		})
	}), nil
}
