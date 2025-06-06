# deletePrefilterHitCount

The deletePrefilterHitCount operation handles configuration related to [/api/fmc_config/v1/domain/{domainUUID}/policy/prefilterpolicies/{containerUUID}/operational/hitcounts](/paths//api/fmc_config/v1/domain/{domain_uuid}/policy/prefilterpolicies/{container_uuid}/operational/hitcounts.md) path.&nbsp;
## Description
**Retrieves, refreshes and clears Hit Count _Check the response section for applicable examples (if any)._**

## Path Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| containerUUID | True | string <td colspan=3> The container id under which this specific resource is contained. |
| domainUUID | True | string <td colspan=3> Domain UUID |

## Query Parameters
| Parameter | Required | Type | Description |
| --------- | -------- | ---- | ----------- |
| filter | True | string <td colspan=3> Value is of format (including quotes): <code>"deviceId:{uuid};ids:{uuid1,uuid2,..};fetchZeroHitCount:{true|false};name:{rule or policy name};lastHit:{number of days as per unit};lastHitUnit:{DAYS|WEEKS|MONTHS|YEARS}"</code><br/><br/><code>deviceId</code> is UUID of device and is a mandatory field.<br/><code>ids</code> returns hitcounts of access rules if set to list of rule UUIDs. If this key is not used, all access rules will be returned.<br/><code>fetchZeroHitCount</code> returns only access rules whose hit count is zero if <code>true</code>.<br/><code>name</code> returns only access rule name or policy name matches<code>name</code>.<br/><code>lastHit</code> returns only access rules hit in last specified number of days as per <code>lastHitUnit</code> unit.<br/><code>lastHitUnit</code> unit of number of last hit days - DAYS, WEEKS, MONTHS or YEARS.<br/><br/>(Note that <code>fetchZeroHitCount</code>,<code>name</code>,<code>lastHit</code>,<code>lastHitUnit</code> filters are applicable only in GET operation and if <code>ids</code> filter is not used) |

## Example
```yaml
- name: Execute 'deletePrefilterHitCount' operation
  cisco.fmcansible.fmc_configuration:
    operation: "deletePrefilterHitCount"
    path_params:
        containerUUID: "{{ container_uuid }}"
        domainUUID: "{{ domain_uuid }}"
    query_params:
        filter: "{{ filter }}"

```