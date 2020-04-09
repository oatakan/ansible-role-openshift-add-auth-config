#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Chris Houseknecht <@chouseknecht>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''

module: k8s

short_description: Manage Kubernetes (K8s) objects

version_added: "2.6"

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Fabian von Feilitzsch (@fabianvf)"

description:
  - Use the OpenShift Python client to perform CRUD operations on K8s objects.
  - Pass the object definition from a source file or inline. See examples for reading
    files and using Jinja templates or vault-encrypted files.
  - Access to the full range of K8s APIs.
  - Use the M(k8s_facts) module to obtain a list of items about an object of type C(kind)
  - Authenticate using either a config file, certificates, password or token.
  - Supports check mode.

extends_documentation_fragment:
  - k8s_state_options
  - k8s_name_options
  - k8s_resource_options
  - k8s_auth_options

options:
  merge_type:
    description:
    - Whether to override the default patch merge approach with a specific type. By default, the strategic
      merge will typically be used.
    - For example, Custom Resource Definitions typically aren't updatable by the usual strategic merge. You may
      want to use C(merge) if you see "strategic merge patch format is not supported"
    - See U(https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/#use-a-json-merge-patch-to-update-a-deployment)
    - Requires openshift >= 0.6.2
    - If more than one merge_type is given, the merge_types will be tried in order
    - If openshift >= 0.6.2, this defaults to C(['strategic-merge', 'merge']), which is ideal for using the same parameters
      on resource kinds that combine Custom Resources and built-in resources. For openshift < 0.6.2, the default
      is simply C(strategic-merge).
    choices:
    - json
    - merge
    - strategic-merge
    type: list
    version_added: "2.7"
  wait:
    description:
    - Whether to wait for certain resource kinds to end up in the desired state. By default the module exits once Kubernetes has
      received the request
    - Implemented for C(state=present) for C(Deployment), C(DaemonSet) and C(Pod), and for C(state=absent) for all resource kinds.
    - For resource kinds without an implementation, C(wait) returns immediately unless C(wait_condition) is set.
    default: no
    type: bool
    version_added: "2.8"
  wait_timeout:
    description:
    - How long in seconds to wait for the resource to end up in the desired state. Ignored if C(wait) is not set.
    default: 120
    version_added: "2.8"
  wait_condition:
    description:
    - Specifies a custom condition on the status to wait for. Ignored if C(wait) is not set or is set to False.
    suboptions:
      type:
        description:
        - The type of condition to wait for. For example, the C(Pod) resource will set the C(Ready) condition (among others)
        - Required if you are specifying a C(wait_condition). If left empty, the C(wait_condition) field will be ignored.
        - The possible types for a condition are specific to each resource type in Kubernetes. See the API documentation of the status field
          for a given resource to see possible choices.
      status:
        description:
        - The value of the status field in your desired condition.
        - For example, if a C(Deployment) is paused, the C(Progressing) C(type) will have the C(Unknown) status.
        choices:
        - True
        - False
        - Unknown
      reason:
        description:
        - The value of the reason field in your desired condition
        - For example, if a C(Deployment) is paused, The C(Progressing) c(type) will have the C(DeploymentPaused) reason.
        - The possible reasons in a condition are specific to each resource type in Kubernetes. See the API documentation of the status field
          for a given resource to see possible choices.
    version_added: "2.8"
  validate:
    description:
      - how (if at all) to validate the resource definition against the kubernetes schema.
        Requires the kubernetes-validate python module
    suboptions:
      fail_on_error:
        description: whether to fail on validation errors.
        required: yes
        type: bool
      version:
        description: version of Kubernetes to validate against. defaults to Kubernetes server version
      strict:
        description: whether to fail when passing unexpected properties
        default: no
        type: bool
    version_added: "2.8"
  append_hash:
    description:
    - Whether to append a hash to a resource name for immutability purposes
    - Applies only to ConfigMap and Secret resources
    - The parameter will be silently ignored for other resource kinds
    - The full definition of an object is needed to generate the hash - this means that deleting an object created with append_hash
      will only work if the same object is passed with state=absent (alternatively, just use state=absent with the name including
      the generated hash and append_hash=no)
    type: bool
    version_added: "2.8"

requirements:
  - "python >= 2.7"
  - "openshift >= 0.6"
  - "PyYAML >= 3.11"
'''

EXAMPLES = '''
- name: Create a k8s namespace
  k8s:
    name: testing
    api_version: v1
    kind: Namespace
    state: present

- name: Create a Service object from an inline definition
  k8s:
    state: present
    definition:
      apiVersion: v1
      kind: Service
      metadata:
        name: web
        namespace: testing
        labels:
          app: galaxy
          service: web
      spec:
        selector:
          app: galaxy
          service: web
        ports:
        - protocol: TCP
          targetPort: 8000
          name: port-8000-tcp
          port: 8000

- name: Create a Service object by reading the definition from a file
  k8s:
    state: present
    src: /testing/service.yml

- name: Remove an existing Service object
  k8s:
    state: absent
    api_version: v1
    kind: Service
    namespace: testing
    name: web

# Passing the object definition from a file

- name: Create a Deployment by reading the definition from a local file
  k8s:
    state: present
    src: /testing/deployment.yml

- name: >-
    Read definition file from the Ansible controller file system.
    If the definition file has been encrypted with Ansible Vault it will automatically be decrypted.
  k8s:
    state: present
    definition: "{{ lookup('file', '/testing/deployment.yml') }}"

- name: Read definition file from the Ansible controller file system after Jinja templating
  k8s:
    state: present
    definition: "{{ lookup('template', '/testing/deployment.yml') }}"

- name: fail on validation errors
  k8s:
    state: present
    definition: "{{ lookup('template', '/testing/deployment.yml') }}"
    validate:
      fail_on_error: yes

- name: warn on validation errors, check for unexpected properties
  k8s:
    state: present
    definition: "{{ lookup('template', '/testing/deployment.yml') }}"
    validate:
      fail_on_error: no
      strict: yes
'''

RETURN = '''
result:
  description:
  - The created, patched, or otherwise present object. Will be empty in the case of a deletion.
  returned: success
  type: complex
  contains:
     api_version:
       description: The versioned schema of this representation of an object.
       returned: success
       type: str
     kind:
       description: Represents the REST resource this object represents.
       returned: success
       type: str
     metadata:
       description: Standard object metadata. Includes name, namespace, annotations, labels, etc.
       returned: success
       type: complex
     spec:
       description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
       returned: success
       type: complex
     status:
       description: Current status details for the object.
       returned: success
       type: complex
     items:
       description: Returned only when multiple yaml documents are passed to src or resource_definition
       returned: when resource_definition or src contains list of objects
       type: list
     duration:
       description: elapsed time of task in seconds
       returned: when C(wait) is true
       type: int
       sample: 48
'''

import copy
from datetime import datetime
from distutils.version import LooseVersion
import time
import sys, os
import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.k8s.common import AUTH_ARG_SPEC, COMMON_ARG_SPEC
from ansible.module_utils.six import string_types
from ansible.module_utils.k8s.common import KubernetesAnsibleModule
from ansible.module_utils.common.dict_transformations import dict_merge

from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils._text import to_native

from distutils.version import LooseVersion


try:
    import yaml
    from openshift.dynamic.exceptions import DynamicApiError, NotFoundError, ConflictError, ForbiddenError, KubernetesValidateMissing
except ImportError:
    # Exceptions handled in common
    pass

try:
    import kubernetes_validate
    HAS_KUBERNETES_VALIDATE = True
except ImportError:
    HAS_KUBERNETES_VALIDATE = False

K8S_CONFIG_HASH_IMP_ERR = None
try:
    from openshift.helper.hashes import generate_hash
    HAS_K8S_CONFIG_HASH = True
except ImportError:
    K8S_CONFIG_HASH_IMP_ERR = traceback.format_exc()
    HAS_K8S_CONFIG_HASH = False

K8S_IMP_ERR = None
try:
    import kubernetes
    import openshift
    from openshift.dynamic import DynamicClient
    from openshift.dynamic.exceptions import ResourceNotFoundError, ResourceNotUniqueError
    HAS_K8S_MODULE_HELPER = True
    k8s_import_exception = None
except ImportError as e:
    HAS_K8S_MODULE_HELPER = False
    k8s_import_exception = e
    K8S_IMP_ERR = traceback.format_exc()

YAML_IMP_ERR = None
try:
    import yaml
    HAS_YAML = True
except ImportError:
    YAML_IMP_ERR = traceback.format_exc()
    HAS_YAML = False

try:
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    pass

class KubernetesRawModule(KubernetesAnsibleModule):

    @property
    def validate_spec(self):
        return dict(
            fail_on_error=dict(type='bool'),
            version=dict(),
            strict=dict(type='bool', default=True)
        )

    @property
    def condition_spec(self):
        return dict(
            type=dict(),
            status=dict(default=True, choices=[True, False, "Unknown"]),
            reason=dict()
        )

    @property
    def argspec(self):
        argument_spec = copy.deepcopy(COMMON_ARG_SPEC)
        argument_spec.update(copy.deepcopy(AUTH_ARG_SPEC))
        argument_spec['merge_type'] = dict(type='list', choices=['json', 'merge', 'strategic-merge'])
        argument_spec['wait'] = dict(type='bool', default=False)
        argument_spec['wait_timeout'] = dict(type='int', default=120)
        argument_spec['wait_condition'] = dict(type='dict', default=None, options=self.condition_spec)
        argument_spec['validate'] = dict(type='dict', default=None, options=self.validate_spec)
        argument_spec['append_hash'] = dict(type='bool', default=False)
        return argument_spec

    def __init__(self, k8s_kind=None, *args, **kwargs):
        self.client = None
        self.warnings = []

        mutually_exclusive = [
            ('resource_definition', 'src'),
        ]

        KubernetesAnsibleModule.__init__(self, *args,
                                         mutually_exclusive=mutually_exclusive,
                                         supports_check_mode=True,
                                         **kwargs)
        self.kind = k8s_kind or self.params.get('kind')
        self.api_version = self.params.get('api_version')
        self.name = self.params.get('name')
        self.namespace = self.params.get('namespace')
        resource_definition = self.params.get('resource_definition')
        validate = self.params.get('validate')
        if validate:
            if LooseVersion(self.openshift_version) < LooseVersion("0.8.0"):
                self.fail_json(msg="openshift >= 0.8.0 is required for validate")
        self.append_hash = self.params.get('append_hash')
        if self.append_hash:
            if not HAS_K8S_CONFIG_HASH:
                self.fail_json(msg=missing_required_lib("openshift >= 0.7.2", reason="for append_hash"),
                               exception=K8S_CONFIG_HASH_IMP_ERR)
        if self.params['merge_type']:
            if LooseVersion(self.openshift_version) < LooseVersion("0.6.2"):
                self.fail_json(msg=missing_required_lib("openshift >= 0.6.2", reason="for merge_type"))
        if resource_definition:
            if isinstance(resource_definition, string_types):
                try:
                    self.resource_definitions = yaml.safe_load_all(resource_definition)
                except (IOError, yaml.YAMLError) as exc:
                    self.fail(msg="Error loading resource_definition: {0}".format(exc))
            elif isinstance(resource_definition, list):
                self.resource_definitions = resource_definition
            else:
                self.resource_definitions = [resource_definition]
        src = self.params.get('src')
        if src:
            self.resource_definitions = self.load_resource_definitions(src)

        if not resource_definition and not src:
            self.resource_definitions = [{
                'kind': self.kind,
                'apiVersion': self.api_version,
                'metadata': {
                    'name': self.name,
                    'namespace': self.namespace
                }
            }]

    def flatten_list_kind(self, list_resource, definitions):
        flattened = []
        parent_api_version = list_resource.group_version if list_resource else None
        parent_kind = list_resource.kind[:-4] if list_resource else None
        for definition in definitions.get('items', []):
            resource = self.find_resource(definition.get('kind', parent_kind), definition.get('apiVersion', parent_api_version), fail=True)
            flattened.append((resource, self.set_defaults(resource, definition)))
        return flattened


    def get_api_client(self, **auth_params):
        auth_args = AUTH_ARG_SPEC.keys()

        auth_params = auth_params or getattr(self, 'params', {})
        auth = copy.deepcopy(auth_params)

        # If authorization variables aren't defined, look for them in environment variables
        for arg in auth_args:
            if auth_params.get(arg) is None:
                env_value = os.getenv('K8S_AUTH_{0}'.format(arg.upper()), None)
                if env_value is not None:
                    if AUTH_ARG_SPEC[arg].get('type') == 'bool':
                        env_value = env_value.lower() not in ['0', 'false', 'no']
                    auth[arg] = env_value

        def auth_set(*names):
            return all([auth.get(name) for name in names])

        if auth_set('username', 'password', 'host') or auth_set('api_key', 'host'):
            # We have enough in the parameters to authenticate, no need to load incluster or kubeconfig
            pass
        elif auth_set('kubeconfig') or auth_set('context'):
            kubernetes.config.load_kube_config(auth.get('kubeconfig'), auth.get('context'))
        else:
            # First try to do incluster config, then kubeconfig
            try:
                kubernetes.config.load_incluster_config()
            except kubernetes.config.ConfigException:
                kubernetes.config.load_kube_config(auth.get('kubeconfig'), auth.get('context'))

        # Override any values in the default configuration with Ansible parameters
        configuration = kubernetes.client.Configuration()
        for key, value in iteritems(auth):
            if key in auth_args and value is not None:
                if key == 'api_key':
                    setattr(configuration, key, {'authorization': "Bearer {0}".format(value)})
                elif key == 'verify_ssl' or key == 'validate_certs':
                    setattr(configuration, 'verify_ssl', value)
                else:
                    setattr(configuration, key, value)
        setattr(configuration, 'verify_ssl', False)

        kubernetes.client.Configuration.set_default(configuration)
        return DynamicClient(kubernetes.client.ApiClient(configuration))

    def execute_module(self):
        changed = False
        results = []
        self.client = self.get_api_client()

        flattened_definitions = []
        for definition in self.resource_definitions:
            kind = definition.get('kind', self.kind)
            api_version = definition.get('apiVersion', self.api_version)
            if kind.endswith('List'):
                resource = self.find_resource(kind, api_version, fail=False)
                flattened_definitions.extend(self.flatten_list_kind(resource, definition))
            else:
                resource = self.find_resource(kind, api_version, fail=True)
                flattened_definitions.append((resource, definition))

        for (resource, definition) in flattened_definitions:
            kind = definition.get('kind', self.kind)
            api_version = definition.get('apiVersion', self.api_version)
            definition = self.set_defaults(resource, definition)
            self.warnings = []
            if self.params['validate'] is not None:
                self.warnings = self.validate(definition)
            result = self.perform_action(resource, definition)
            result['warnings'] = self.warnings
            changed = changed or result['changed']
            results.append(result)

        if len(results) == 1:
            self.exit_json(**results[0])

        self.exit_json(**{
            'changed': changed,
            'result': {
                'results': results
            }
        })

    def validate(self, resource):
        def _prepend_resource_info(resource, msg):
            return "%s %s: %s" % (resource['kind'], resource['metadata']['name'], msg)

        try:
            warnings, errors = self.client.validate(resource, self.params['validate'].get('version'), self.params['validate'].get('strict'))
        except KubernetesValidateMissing:
            self.fail_json(msg="kubernetes-validate python library is required to validate resources")

        if errors and self.params['validate']['fail_on_error']:
            self.fail_json(msg="\n".join([_prepend_resource_info(resource, error) for error in errors]))
        else:
            return [_prepend_resource_info(resource, msg) for msg in warnings + errors]

    def set_defaults(self, resource, definition):
        definition['kind'] = resource.kind
        definition['apiVersion'] = resource.group_version
        metadata = definition.get('metadata', {})
        if self.name and not metadata.get('name'):
            metadata['name'] = self.name
        if resource.namespaced and self.namespace and not metadata.get('namespace'):
            metadata['namespace'] = self.namespace
        definition['metadata'] = metadata
        return definition

    def perform_action(self, resource, definition):
        result = {'changed': False, 'result': {}}
        state = self.params.get('state', None)
        force = self.params.get('force', False)
        name = definition['metadata'].get('name')
        namespace = definition['metadata'].get('namespace')
        existing = None
        wait = self.params.get('wait')
        wait_timeout = self.params.get('wait_timeout')
        wait_condition = None
        if self.params.get('wait_condition') and self.params['wait_condition'].get('type'):
            wait_condition = self.params['wait_condition']

        self.remove_aliases()

        try:
            # ignore append_hash for resources other than ConfigMap and Secret
            if self.append_hash and definition['kind'] in ['ConfigMap', 'Secret']:
                name = '%s-%s' % (name, generate_hash(definition))
                definition['metadata']['name'] = name
            params = dict(name=name, namespace=namespace)
            existing = resource.get(**params)
        except NotFoundError:
            # Remove traceback so that it doesn't show up in later failures
            try:
                sys.exc_clear()
            except AttributeError:
                # no sys.exc_clear on python3
                pass
        except ForbiddenError as exc:
            if definition['kind'] in ['Project', 'ProjectRequest'] and state != 'absent':
                return self.create_project_request(definition)
            self.fail_json(msg='Failed to retrieve requested object: {0}'.format(exc.body),
                           error=exc.status, status=exc.status, reason=exc.reason)
        except DynamicApiError as exc:
            self.fail_json(msg='Failed to retrieve requested object: {0}'.format(exc.body),
                           error=exc.status, status=exc.status, reason=exc.reason)

        if state == 'absent':
            result['method'] = "delete"
            if not existing:
                # The object already does not exist
                return result
            else:
                # Delete the object
                result['changed'] = True
                if not self.check_mode:
                    try:
                        k8s_obj = resource.delete(**params)
                        result['result'] = k8s_obj.to_dict()
                    except DynamicApiError as exc:
                        self.fail_json(msg="Failed to delete object: {0}".format(exc.body),
                                       error=exc.status, status=exc.status, reason=exc.reason)
                    if wait:
                        success, resource, duration = self.wait(resource, definition, wait_timeout, 'absent')
                        result['duration'] = duration
                        if not success:
                            self.fail_json(msg="Resource deletion timed out", **result)
                return result
        else:
            if not existing:
                if self.check_mode:
                    k8s_obj = definition
                else:
                    try:
                        k8s_obj = resource.create(definition, namespace=namespace).to_dict()
                    except ConflictError:
                        # Some resources, like ProjectRequests, can't be created multiple times,
                        # because the resources that they create don't match their kind
                        # In this case we'll mark it as unchanged and warn the user
                        self.warn("{0} was not found, but creating it returned a 409 Conflict error. This can happen \
                                  if the resource you are creating does not directly create a resource of the same kind.".format(name))
                        return result
                    except DynamicApiError as exc:
                        msg = "Failed to create object: {0}".format(exc.body)
                        if self.warnings:
                            msg += "\n" + "\n    ".join(self.warnings)
                        self.fail_json(msg=msg, error=exc.status, status=exc.status, reason=exc.reason)
                success = True
                result['result'] = k8s_obj
                if wait and not self.check_mode:
                    success, result['result'], result['duration'] = self.wait(resource, definition, wait_timeout, condition=wait_condition)
                result['changed'] = True
                result['method'] = 'create'
                if not success:
                    self.fail_json(msg="Resource creation timed out", **result)
                return result

            match = False
            diffs = []

            if existing and force:
                if self.check_mode:
                    k8s_obj = definition
                else:
                    try:
                        k8s_obj = resource.replace(definition, name=name, namespace=namespace, append_hash=self.append_hash).to_dict()
                    except DynamicApiError as exc:
                        msg = "Failed to replace object: {0}".format(exc.body)
                        if self.warnings:
                            msg += "\n" + "\n    ".join(self.warnings)
                        self.fail_json(msg=msg, error=exc.status, status=exc.status, reason=exc.reason)
                match, diffs = self.diff_objects(existing.to_dict(), k8s_obj)
                success = True
                result['result'] = k8s_obj
                if wait:
                    success, result['result'], result['duration'] = self.wait(resource, definition, wait_timeout, condition=wait_condition)
                match, diffs = self.diff_objects(existing.to_dict(), result['result'].to_dict())
                result['changed'] = not match
                result['method'] = 'replace'
                result['diff'] = diffs
                if not success:
                    self.fail_json(msg="Resource replacement timed out", **result)
                return result

            # Differences exist between the existing obj and requested params
            if self.check_mode:
                k8s_obj = dict_merge(existing.to_dict(), definition)
            else:
                if LooseVersion(self.openshift_version) < LooseVersion("0.6.2"):
                    k8s_obj, error = self.patch_resource(resource, definition, existing, name,
                                                         namespace)
                else:
                    for merge_type in self.params['merge_type'] or ['strategic-merge', 'merge']:
                        k8s_obj, error = self.patch_resource(resource, definition, existing, name,
                                                             namespace, merge_type=merge_type)
                        if not error:
                            break
                if error:
                    self.fail_json(**error)

            success = True
            result['result'] = k8s_obj
            if wait:
                success, result['result'], result['duration'] = self.wait(resource, definition, wait_timeout, condition=wait_condition)
            match, diffs = self.diff_objects(existing.to_dict(), result['result'])
            result['result'] = k8s_obj
            result['changed'] = not match
            result['method'] = 'patch'
            result['diff'] = diffs

            if not success:
                self.fail_json(msg="Resource update timed out", **result)
            return result

    def patch_resource(self, resource, definition, existing, name, namespace, merge_type=None):
        try:
            params = dict(name=name, namespace=namespace)
            if merge_type:
                params['content_type'] = 'application/{0}-patch+json'.format(merge_type)
            k8s_obj = resource.patch(definition, **params).to_dict()
            match, diffs = self.diff_objects(existing.to_dict(), k8s_obj)
            error = {}
            return k8s_obj, {}
        except DynamicApiError as exc:
            msg = "Failed to patch object: {0}".format(exc.body)
            if self.warnings:
                msg += "\n" + "\n    ".join(self.warnings)
            error = dict(msg=msg, error=exc.status, status=exc.status, reason=exc.reason, warnings=self.warnings)
            return None, error

    def create_project_request(self, definition):
        definition['kind'] = 'ProjectRequest'
        result = {'changed': False, 'result': {}}
        resource = self.find_resource('ProjectRequest', definition['apiVersion'], fail=True)
        if not self.check_mode:
            try:
                k8s_obj = resource.create(definition)
                result['result'] = k8s_obj.to_dict()
            except DynamicApiError as exc:
                self.fail_json(msg="Failed to create object: {0}".format(exc.body),
                               error=exc.status, status=exc.status, reason=exc.reason)
        result['changed'] = True
        result['method'] = 'create'
        return result

    def _wait_for(self, resource, name, namespace, predicate, timeout, state):
        start = datetime.now()

        def _wait_for_elapsed():
            return (datetime.now() - start).seconds

        response = None
        while _wait_for_elapsed() < timeout:
            try:
                response = resource.get(name=name, namespace=namespace)
                if predicate(response):
                    if response:
                        return True, response.to_dict(), _wait_for_elapsed()
                    else:
                        return True, {}, _wait_for_elapsed()
                time.sleep(timeout // 20)
            except NotFoundError:
                if state == 'absent':
                    return True, {}, _wait_for_elapsed()
        if response:
            response = response.to_dict()
        return False, response, _wait_for_elapsed()

    def wait(self, resource, definition, timeout, state='present', condition=None):

        def _deployment_ready(deployment):
            # FIXME: frustratingly bool(deployment.status) is True even if status is empty
            # Furthermore deployment.status.availableReplicas == deployment.status.replicas == None if status is empty
            return (deployment.status and deployment.status.replicas is not None and
                    deployment.status.availableReplicas == deployment.status.replicas and
                    deployment.status.observedGeneration == deployment.metadata.generation)

        def _pod_ready(pod):
            return (pod.status and pod.status.containerStatuses is not None and
                    all([container.ready for container in pod.status.containerStatuses]))

        def _daemonset_ready(daemonset):
            return (daemonset.status and daemonset.status.desiredNumberScheduled is not None and
                    daemonset.status.numberReady == daemonset.status.desiredNumberScheduled and
                    daemonset.status.observedGeneration == daemonset.metadata.generation)

        def _custom_condition(resource):
            if not resource.status or not resource.status.conditions:
                return False
            match = [x for x in resource.status.conditions if x.type == condition['type']]
            if not match:
                return False
            # There should never be more than one condition of a specific type
            match = match[0]
            if match.status == 'Unknown':
                return False
            status = True if match.status == 'True' else False
            if status == condition['status']:
                if condition.get('reason'):
                    return match.reason == condition['reason']
                return True
            return False

        def _resource_absent(resource):
            return not resource

        waiter = dict(
            Deployment=_deployment_ready,
            DaemonSet=_daemonset_ready,
            Pod=_pod_ready
        )
        kind = definition['kind']
        if state == 'present' and not condition:
            predicate = waiter.get(kind, lambda x: x)
        elif state == 'present' and condition:
            predicate = _custom_condition
        else:
            predicate = _resource_absent
        return self._wait_for(resource, definition['metadata']['name'], definition['metadata'].get('namespace'), predicate, timeout, state)


def main():
    KubernetesRawModule().execute_module()


if __name__ == '__main__':
    main()