# deleteIPv6AddressPool

The deleteIPv6AddressPool operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/object/ipv6addresspools/{objectId}](/paths//api/fmc_config/v1/domain/{domain_uuid}/object/ipv6addresspools/{object_id}.md) path.&nbsp;
## Description
**Retrieves the IPv6 Address Pool object associated with the specified ID. If no ID is specified for a GET, retrieves list of all IPv6 Address Pool objects. _Check the response section for applicable examples (if any)._**

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| objectId | True | string <td colspan=3> Unique identifier of the object. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Example
```yaml
- name: Execute 'deleteIPv6AddressPool' operation
  cisco.fmcansible.fmc_configuration:
    operation: "deleteIPv6AddressPool"
    path_params:
        objectId: "{{ object_id }}"
        domainUUID: "{{ domain_uuid }}"

```