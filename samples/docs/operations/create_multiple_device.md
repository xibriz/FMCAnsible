# createMultipleDevice

The createMultipleDevice operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords](/paths//api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords.md) path.&nbsp;
## Description
**Retrieves or modifies the device record associated with the specified ID. Registers or unregisters a device. If no ID is specified for a GET, retrieves list of all device records. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| name | <name> |
| hostName | <host name> |
| natID | cisco123 |
| regKey | regkey |
| type | Device |
| license_caps | ['MALWARE', 'URLFilter', 'PROTECT', 'CONTROL', 'VPN'] |
| accessPolicy | {'id': 'accessPolicyUUID', 'type': 'AccessPolicy'} |

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Query Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| bulk | False | boolean <td colspan=3> Enables bulk registration or unregistration for devices. |

## Example
```yaml
- name: Execute 'createMultipleDevice' operation
  cisco.fmcansible.fmc_configuration:
    operation: "createMultipleDevice"
    data:
        name: <name>
        hostName: <host name>
        natID: cisco123
        regKey: regkey
        type: Device
        license_caps: ['MALWARE', 'URLFilter', 'PROTECT', 'CONTROL', 'VPN']
        accessPolicy: {'id': 'accessPolicyUUID', 'type': 'AccessPolicy'}
    path_params:
        domainUUID: "{{ domain_uuid }}"
    query_params:
        bulk: "{{ bulk }}"

```