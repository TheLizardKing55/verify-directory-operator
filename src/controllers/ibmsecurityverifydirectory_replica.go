/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to handle
 * the creation of the replica controller
 */

/*****************************************************************************/

import (
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1  "k8s.io/api/core/v1"
	batchv1 "k8s.io/api/batch/v1"

	"fmt"
	"strconv"
  "bytes"
	"errors"
  "reflect"
	"strings"
	"time"

	"github.com/go-yaml/yaml"
	"github.com/ibm-security/verify-directory-operator/utils"

	ctrl "sigs.k8s.io/controller-runtime"

  "sigs.k8s.io/controller-runtime/pkg/client"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*****************************************************************************/

/*
*
*/

func (r *IBMSecurityVerifyDirectoryReconciler) deployReplicaController(
			h          *RequestHandle,
			existing   map[string]string,
			toBeAdded  []string) (map[string]string, error) {

	var err error = nil

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "deployReplicaController")...)

	/*
	 * Don't do anything here if there is nothing to be added.
	 */

	if len(toBeAdded) == 0 {
		return existing, nil
	}

	} else {

		/*
	         * We now want to create/restart the replica controller.
	         */
  
		var pod string

		err = r.createReplicaController(h, port, updated)

			if err != nil {
			return nil, err
		}
