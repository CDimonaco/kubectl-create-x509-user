package roles_test

import (
	"context"
	"testing"

	"github.com/cdimonaco/kubectl-create-x509-user/internal/roles"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGroupExistsInClusterRoleBindings(t *testing.T) {
	type testCase struct {
		expectedResult            bool
		mockedClusterRoleBindings v1.ClusterRoleBindingList
		shouldError               bool
		expectedError             string
		inputGroup                string
	}

	for tn, tc := range map[string]testCase{
		"should return true and no error when group is found on cluster role bindings": {
			expectedResult: true,
			shouldError:    false,
			inputGroup:     "system:masters",
			mockedClusterRoleBindings: v1.ClusterRoleBindingList{
				Items: []v1.ClusterRoleBinding{
					{
						Subjects: []v1.Subject{
							{
								Kind: "Group",
								Name: "system:masters",
							},
						},
					},
				},
			},
		},
		"should return false and no error when the group is not found on cluster role bindings": {
			expectedResult: false,
			shouldError:    false,
			inputGroup:     "system:masters",
			mockedClusterRoleBindings: v1.ClusterRoleBindingList{
				Items: []v1.ClusterRoleBinding{
					{
						Subjects: []v1.Subject{
							{
								Kind: "Group",
								Name: "rio:masters",
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tn, func(t *testing.T) {
			testClient := fake.NewSimpleClientset(&tc.mockedClusterRoleBindings)
			result, err := roles.GroupExistsInClusterRoleBindings(
				context.Background(),
				testClient.RbacV1(),
				tc.inputGroup,
			)
			if tc.shouldError {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.expectedError)
				assert.False(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}
