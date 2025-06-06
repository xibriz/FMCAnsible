# createMultipleFTDManualNatRule

The createMultipleFTDManualNatRule operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/policy/ftdnatpolicies/{containerUUID}/manualnatrules](/paths//api/fmc_config/v1/domain/{domain_uuid}/policy/ftdnatpolicies/{container_uuid}/manualnatrules.md) path.&nbsp;
## Description
**Retrieves, deletes, creates, or modifies the Manual NAT rule associated with the specified ID. Also, retrieves list of all Manual NAT rules. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| originalDestinationPort | {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'} |
| originalSource | {'type': 'Network', 'id': 'Network object uuid'} |
| originalSourcePort | {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'} |
| translatedDestination | {'type': 'Network', 'id': 'Network object uuid'} |
| translatedDestinationPort | {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'} |
| translatedSource | {'type': 'Network', 'id': 'network object uuid'} |
| translatedSourcePort | {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'} |
| unidirectional | False |
| originalDestination | {'type': 'Network', 'id': 'network object uuid'} |
| interfaceInOriginalDestination | False |
| type | FTDManualNatRule |
| enabled | True |
| natType | STATIC |
| interfaceIpv6 | False |
| fallThrough | False |
| dns | False |
| routeLookup | False |
| noProxyArp | False |
| netToNet | False |
| sourceInterface | {'id': 'security zone uuid', 'type': 'SecurityZone'} |
| destinationInterface | {'id': 'security zone uuid', 'type': 'SecurityZone'} |
| description | description of nat rule |

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| containerUUID | True | string <td colspan=3> The container id under which this specific resource is contained. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Query Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| bulk | False | boolean <td colspan=3> Enables bulk actions for Manual NAT rules. |
| section | False | string <td colspan=3> Retrieves, creates or modifies manual nat rule in given section. Allowed value is before_auto and after_auto. |
| targetIndex | False | string <td colspan=3> Creates or modifies manual nat rule at given targetIndex. It takes an integer value. |

## Example
```yaml
- name: Execute 'createMultipleFTDManualNatRule' operation
  cisco.fmcansible.fmc_configuration:
    operation: "createMultipleFTDManualNatRule"
    data:
        originalDestinationPort: {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'}
        originalSource: {'type': 'Network', 'id': 'Network object uuid'}
        originalSourcePort: {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'}
        translatedDestination: {'type': 'Network', 'id': 'Network object uuid'}
        translatedDestinationPort: {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'}
        translatedSource: {'type': 'Network', 'id': 'network object uuid'}
        translatedSourcePort: {'type': 'ProtocolPortObject', 'id': 'protocol port object uuid'}
        unidirectional: False
        originalDestination: {'type': 'Network', 'id': 'network object uuid'}
        interfaceInOriginalDestination: False
        type: FTDManualNatRule
        enabled: True
        natType: STATIC
        interfaceIpv6: False
        fallThrough: False
        dns: False
        routeLookup: False
        noProxyArp: False
        netToNet: False
        sourceInterface: {'id': 'security zone uuid', 'type': 'SecurityZone'}
        destinationInterface: {'id': 'security zone uuid', 'type': 'SecurityZone'}
        description: description of nat rule
    path_params:
        containerUUID: "{{ container_uuid }}"
        domainUUID: "{{ domain_uuid }}"
    query_params:
        bulk: "{{ bulk }}"
        section: "{{ section }}"
        targetIndex: "{{ target_index }}"

```