# updateBFDPolicyModel

The updateBFDPolicyModel operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{containerUUID}/routing/bfdpolicies/{objectId}](/paths//api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{container_uuid}/routing/bfdpolicies/{object_id}.md) path.&nbsp;
## Description
**Retrieves, deletes, creates, or modifies the BFD Policy associated with the specified ID. If no ID is specified for a GET, retrieves list of all BFD Policies. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| type | BFDPolicy |
| hopType | SINGLE_HOP |
| id | bfdPolicyUUid |
| interface | {'id': 'interface_uuid', 'type': 'PhysicalInterface', 'name': 'GigabitEthernet1/1'} |
| template | {'id': 'template_uuid', 'type': 'BFDTemplate', 'name': 'SingleHopTemplate1'} |

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| objectId | True | string <td colspan=3> Unique identifier of a BFD Policy. |
| containerUUID | True | string <td colspan=3> The container id under which this specific resource is contained. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Example
```yaml
- name: Execute 'updateBFDPolicyModel' operation
  cisco.fmcansible.fmc_configuration:
    operation: "updateBFDPolicyModel"
    data:
        type: BFDPolicy
        hopType: SINGLE_HOP
        id: bfdPolicyUUid
        interface: {'id': 'interface_uuid', 'type': 'PhysicalInterface', 'name': 'GigabitEthernet1/1'}
        template: {'id': 'template_uuid', 'type': 'BFDTemplate', 'name': 'SingleHopTemplate1'}
    path_params:
        objectId: "{{ object_id }}"
        containerUUID: "{{ container_uuid }}"
        domainUUID: "{{ domain_uuid }}"

```