# updateFPLogicalInterface

The updateFPLogicalInterface operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{containerUUID}/fplogicalinterfaces/{objectId}](/paths//api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{container_uuid}/fplogicalinterfaces/{object_id}.md) path.&nbsp;
## Description
**Retrieves, deletes, creates, or modifies the logical interface associated with the specified NGIPS device ID and interface ID. If no ID is specified, retrieves list of all logical interfaces associated with the specified NGIPS device ID. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| name | hybrid_1 |
| type | FPLogicalInterface |
| id | fplogicalinterfaceUUID3 |
| enabled | 0 |
| ipAddresses | ['10.1.1.2/18', '10.11.12.13/19'] |
| interfaceType | VLAN |

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| objectId | True | string <td colspan=3> Unique identifier of a logical interface. |
| containerUUID | True | string <td colspan=3> The container id under which this specific resource is contained. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Example
```yaml
- name: Execute 'updateFPLogicalInterface' operation
  cisco.fmcansible.fmc_configuration:
    operation: "updateFPLogicalInterface"
    data:
        name: hybrid_1
        type: FPLogicalInterface
        id: fplogicalinterfaceUUID3
        enabled: 0
        ipAddresses: ['10.1.1.2/18', '10.11.12.13/19']
        interfaceType: VLAN
    path_params:
        objectId: "{{ object_id }}"
        containerUUID: "{{ container_uuid }}"
        domainUUID: "{{ domain_uuid }}"

```