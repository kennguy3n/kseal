// Package templates embeds the per-sink onboarding configuration assets that
// operators install on the SIEM side to parse kseal's minimized export schema:
// Splunk props/transforms.conf, a Microsoft Sentinel Data Collection Rule, and
// an Elastic ECS index template. They are embedded (not just docs) so the
// console and CLI can serve the exact, version-matched config to download.
package templates

import _ "embed"

//go:embed splunk_props.conf
var SplunkProps string

//go:embed splunk_transforms.conf
var SplunkTransforms string

//go:embed sentinel_dcr.json
var SentinelDCR string

//go:embed elastic_ecs_index_template.json
var ElasticECSIndexTemplate string
