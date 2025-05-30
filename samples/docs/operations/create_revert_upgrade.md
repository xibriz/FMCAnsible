# createRevertUpgrade

The createRevertUpgrade operation handles configuration related to [/api/fmc_platform/v1/updates/revertupgrades](/paths//api/fmc_platform/v1/updates/revertupgrades.md) path.&nbsp;
## Description
**Creates a task to revert an upgrade on an FTD. _Check the response section for applicable examples (if any)._**

## Data Parameters Example
| Parameter | Value |
| --------- | -------- |
| targets | [{'id': '1251b782-7922-11e8-85d1-9ce8632d3182', 'type': 'Device', 'name': 'vFTD-1'}, {'id': '88f052b8-7922-11e8-a602-840c6cea8ca5', 'type': 'Device', 'name': 'vFTD-2'}] |

## Example
```yaml
- name: Execute 'createRevertUpgrade' operation
  cisco.fmcansible.fmc_configuration:
    operation: "createRevertUpgrade"
    data:
        targets: [{'id': '1251b782-7922-11e8-85d1-9ce8632d3182', 'type': 'Device', 'name': 'vFTD-1'}, {'id': '88f052b8-7922-11e8-a602-840c6cea8ca5', 'type': 'Device', 'name': 'vFTD-2'}]

```