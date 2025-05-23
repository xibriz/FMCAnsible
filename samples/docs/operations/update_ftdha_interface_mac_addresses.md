# updateFTDHAInterfaceMACAddresses

The updateFTDHAInterfaceMACAddresses operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/devicehapairs/ftddevicehapairs/{containerUUID}/failoverinterfacemacaddressconfigs/{objectId}](/paths//api/fmc_config/v1/domain/{domain_uuid}/devicehapairs/ftddevicehapairs/{container_uuid}/failoverinterfacemacaddressconfigs/{object_id}.md) path.&nbsp;
## Description
**Retrieves or modifies the Firewall Threat Defense HA failover policy interface MAC addresses record associated with the specified Firewall Threat Defense HA pair. If no ID is specified for a GET, retrieves list of all Firewall Threat Defense HA failover policy interface MAC addresses records. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| id | <failover_interface_mac-address_uuid> |
| type | FailoverInterfaceMACAddressConfig |
| failoverActiveMac | 0050.56a9.603c |
| failoverStandbyMac | 0050.56a9.603d |

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| objectId | True | string <td colspan=3> Identifier of a Firewall Threat Defense HA failover policy interface MAC addresses. |
| containerUUID | True | string <td colspan=3> The container id under which this specific resource is contained. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Example
```yaml
- name: Execute 'updateFTDHAInterfaceMACAddresses' operation
  cisco.fmcansible.fmc_configuration:
    operation: "updateFTDHAInterfaceMACAddresses"
    data:
        id: <failover_interface_mac-address_uuid>
        type: FailoverInterfaceMACAddressConfig
        failoverActiveMac: 0050.56a9.603c
        failoverStandbyMac: 0050.56a9.603d
    path_params:
        objectId: "{{ object_id }}"
        containerUUID: "{{ container_uuid }}"
        domainUUID: "{{ domain_uuid }}"

```