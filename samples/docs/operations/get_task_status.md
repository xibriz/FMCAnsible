# getTaskStatus

The getTaskStatus operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/job/taskstatuses/{objectId}](/paths//api/fmc_config/v1/domain/{domain_uuid}/job/taskstatuses/{object_id}.md) path.&nbsp;
## Description
**Retrieves information about a previously submitted pending job/task with the specified ID.**

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| objectId | True | string <td colspan=3> UUID of request. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Query Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| showDetailedDeviceStatus | False | boolean <td colspan=3> Query parameter to show the detailed status of devices for type : DEVICE_DEPLOYMENT and DEVICE_ROLLBACK |

## Example
```yaml
- name: Execute 'getTaskStatus' operation
  cisco.fmcansible.fmc_configuration:
    operation: "getTaskStatus"
    path_params:
        objectId: "{{ object_id }}"
        domainUUID: "{{ domain_uuid }}"
    query_params:
        showDetailedDeviceStatus: "{{ show_detailed_device_status }}"

```