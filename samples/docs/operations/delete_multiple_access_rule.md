# deleteMultipleAccessRule

The deleteMultipleAccessRule operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{containerUUID}/accessrules](/paths//api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{container_uuid}/accessrules.md) path.&nbsp;
## Description
**Retrieves, deletes, creates, or modifies the access control rule associated with the specified policy ID and rule ID. If no ID is specified, retrieves list of all access rules associated with the specified policy ID. _Check the response section for applicable examples (if any)._**

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| containerUUID | True | string <td colspan=3> The container id under which this specific resource is contained. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Query Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| bulk | True | boolean <td colspan=3> This parameter specifies that bulk operation is being used in the query. This parameter is required for bulk rule operations. |
| filter | True | string <td colspan=3> For bulk delete needs the filter="ids:" and with <code>bulk=true</code> flag, Value is of format (including quotes): <code>"ids:id1,id2,..."</code>.<br/><code>ids</code> is a comma-separated list of rule IDs to be deleted. For GetAll Filter criteria can be specified using the format <code>"name:filterName;timeRange:yes/no;action:filterAction;sourceNetworks:filterValue1,filterValue2...."</code>. Supported filter criteria are "name","timeRange","action","sourceNetworks","destinationNetworks","sourcePorts","destinationPorts","sourceZones","destinationZones","applications","sourceDynamicObjects","destinationDynamicObjects","vlanTags","comments","users","urls","intrusionPolicy","sourceSecurityGroupTags","fts". |

## Example
```yaml
- name: Execute 'deleteMultipleAccessRule' operation
  cisco.fmcansible.fmc_configuration:
    operation: "deleteMultipleAccessRule"
    path_params:
        containerUUID: "{{ container_uuid }}"
        domainUUID: "{{ domain_uuid }}"
    query_params:
        bulk: "{{ bulk }}"
        filter: "{{ filter }}"

```