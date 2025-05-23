# updatePortObjectGroup

The updatePortObjectGroup operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups/{objectId}](/paths//api/fmc_config/v1/domain/{domain_uuid}/object/portobjectgroups/{object_id}.md) path.&nbsp;
## Description
**Retrieves, deletes, creates, or modifies the port object group object associated with the specified ID. If no ID is specified for a GET, retrieves list of all port object group objects. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| id | PortGroupObjUUID |
| name | portgroup_obj1_updated |
| type | PortObjectGroup |
| objects | [{'type': 'ICMPV4Object', 'id': 'ICMPV4ObjectUUID'}, {'id': 'ICMPV6ObjectUUID', 'type': 'ICMPV6Object'}, {'id': 'ProtocolPortObjectUUID', 'type': 'ProtocolPortObject'}] |

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| objectId | True | string <td colspan=3> Unique identifier of the port object group. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Example
```yaml
- name: Execute 'updatePortObjectGroup' operation
  cisco.fmcansible.fmc_configuration:
    operation: "updatePortObjectGroup"
    data:
        id: PortGroupObjUUID
        name: portgroup_obj1_updated
        type: PortObjectGroup
        objects: [{'type': 'ICMPV4Object', 'id': 'ICMPV4ObjectUUID'}, {'id': 'ICMPV6ObjectUUID', 'type': 'ICMPV6Object'}, {'id': 'ProtocolPortObjectUUID', 'type': 'ProtocolPortObject'}]
    path_params:
        objectId: "{{ object_id }}"
        domainUUID: "{{ domain_uuid }}"

```