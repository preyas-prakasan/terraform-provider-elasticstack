package clients

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/terraform-provider-elasticstack/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type CompositeId struct {
	ClusterId  string
	ResourceId string
}

func CompositeIdFromStr(id string) (*CompositeId, diag.Diagnostics) {
	var diags diag.Diagnostics
	idParts := strings.Split(id, "/")
	if len(idParts) != 2 {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Wrong resource ID.",
			Detail:   "Resource ID must have following format: <cluster_uuid>/<resource identifier>",
		})
		return nil, diags
	}
	return &CompositeId{
			ClusterId:  idParts[0],
			ResourceId: idParts[1],
		},
		diags
}

func ResourceIDFromStr(id string) (string, diag.Diagnostics) {
	compID, diags := CompositeIdFromStr(id)
	if diags.HasError() {
		return "", diags
	}
	return compID.ResourceId, nil
}

func (c *CompositeId) String() string {
	return fmt.Sprintf("%s/%s", c.ClusterId, c.ResourceId)
}

type ApiClient struct {
	es      *elasticsearch.Client
	version string
}

func NewApiClientFunc(version string) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		config, diags := newEsConfigFromResourceData(d, "elasticsearch", version, true)

		if diags.HasError() {
			return nil, diags
		}

		if config == nil {
			return nil, diag.Errorf("Unable to read connection config for provider")
		}

		es, err := elasticsearch.NewClient(*config)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to create Elasticsearch client",
				Detail:   err.Error(),
			})
		}
		if logging.IsDebugOrHigher() {
			es.Transport = newDebugTransport("elasticsearch", es.Transport)
		}
		return &ApiClient{es, version}, diags
	}
}

func NewAcceptanceTestingClient() (*ApiClient, error) {
	config := elasticsearch.Config{}
	config.Header = http.Header{"User-Agent": []string{"elasticstack-terraform-provider/tf-acceptance-testing"}}

	if es := os.Getenv("ELASTICSEARCH_ENDPOINTS"); es != "" {
		endpoints := make([]string, 0)
		for _, e := range strings.Split(es, ",") {
			endpoints = append(endpoints, strings.TrimSpace(e))
		}
		config.Addresses = endpoints
	}

	if username := os.Getenv("ELASTICSEARCH_USERNAME"); username != "" {
		config.Username = username
		config.Password = os.Getenv("ELASTICSEARCH_PASSWORD")
	} else {
		config.APIKey = os.Getenv("ELASTICSEARCH_API_KEY")
	}

	es, err := elasticsearch.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &ApiClient{es, "acceptance-testing"}, nil
}

func NewApiClient(d *schema.ResourceData, meta interface{}) (*ApiClient, diag.Diagnostics) {
	defaultClient := meta.(*ApiClient)
	resourceConfig, diags := newEsConfigFromResourceData(d, "elasticsearch_connection", defaultClient.version, false)
	if diags.HasError() {
		return nil, diags
	}

	// if the config provided let's use it
	if resourceConfig != nil {
		es, err := elasticsearch.NewClient(*resourceConfig)
		if err != nil {
			return nil, diag.Errorf("Unable to create Elasticsearch client %s", err)
		}
		if logging.IsDebugOrHigher() {
			es.Transport = newDebugTransport("elasticsearch", es.Transport)
		}
		return &ApiClient{es, defaultClient.version}, nil
	} else { // or return the default client
		return defaultClient, nil
	}
}

func newEsConfigFromResourceData(d *schema.ResourceData, fieldName string, version string, useEnvAsDefault bool) (*elasticsearch.Config, diag.Diagnostics) {
	providerConfigs, ok := d.GetOk(fieldName)
	if !ok {
		return nil, nil
	}

	config := elasticsearch.Config{}
	config.Header = http.Header{"User-Agent": []string{fmt.Sprintf("elasticstack-terraform-provider/%s", version)}}

	providerConfig, ok := providerConfigs.([]interface{})[0].(map[string]interface{})
	if !ok || providerConfig == nil {
		return nil, diag.Errorf("could not read connection configuration from module")
	}

	if username, ok := providerConfig["username"]; ok {
		config.Username = username.(string)
	}
	if password, ok := providerConfig["password"]; ok {
		config.Password = password.(string)
	}
	if apikey, ok := providerConfig["api_key"]; ok {
		config.APIKey = apikey.(string)
	}

	// default endpoints taken from Env if set
	if es := os.Getenv("ELASTICSEARCH_ENDPOINTS"); useEnvAsDefault && es != "" {
		endpoints := make([]string, 0)
		for _, e := range strings.Split(es, ",") {
			endpoints = append(endpoints, strings.TrimSpace(e))
		}
		config.Addresses = endpoints
	}
	// setting endpoints from config block if provided
	if eps, ok := providerConfig["endpoints"]; ok && len(eps.([]interface{})) > 0 {
		endpoints := make([]string, 0)
		for _, e := range eps.([]interface{}) {
			endpoints = append(endpoints, e.(string))
		}
		config.Addresses = endpoints
	}

	if insecure, ok := providerConfig["insecure"]; ok && insecure.(bool) {
		tlsClientConfig := ensureTLSClientConfig(&config)
		tlsClientConfig.InsecureSkipVerify = true
	}

	if caFile, ok := providerConfig["ca_file"]; ok && caFile.(string) != "" {
		caCert, err := os.ReadFile(caFile.(string))
		if err != nil {
			return nil, diag.Diagnostics{diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to read CA File",
				Detail:   err.Error(),
			}}
		}
		config.CACert = caCert
	}
	if caData, ok := providerConfig["ca_data"]; ok && caData.(string) != "" {
		config.CACert = []byte(caData.(string))
	}

	if certFile, ok := providerConfig["cert_file"]; ok && certFile.(string) != "" {
		if keyFile, ok := providerConfig["key_file"]; ok && keyFile.(string) != "" {
			cert, err := tls.LoadX509KeyPair(certFile.(string), keyFile.(string))
			if err != nil {
				return nil, diag.Diagnostics{diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Unable to read certificate or key file",
					Detail:   err.Error(),
				}}
			}
			tlsClientConfig := ensureTLSClientConfig(&config)
			tlsClientConfig.Certificates = []tls.Certificate{cert}
		} else {
			return nil, diag.Diagnostics{diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to read key file",
				Detail:   "Path to key file has not been configured or is empty",
			}}
		}
	}
	if certData, ok := providerConfig["cert_data"]; ok && certData.(string) != "" {
		if keyData, ok := providerConfig["key_data"]; ok && keyData.(string) != "" {
			cert, err := tls.X509KeyPair([]byte(certData.(string)), []byte(keyData.(string)))
			if err != nil {
				return nil, diag.Diagnostics{diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Unable to parse certificate or key",
					Detail:   err.Error(),
				}}
			}
			tlsClientConfig := ensureTLSClientConfig(&config)
			tlsClientConfig.Certificates = []tls.Certificate{cert}
		} else {
			return nil, diag.Diagnostics{diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to parse key",
				Detail:   "Key data has not been configured or is empty",
			}}
		}
	}

	return &config, nil
}

func ensureTLSClientConfig(config *elasticsearch.Config) *tls.Config {
	if config.Transport == nil {
		config.Transport = http.DefaultTransport.(*http.Transport)
	}
	if config.Transport.(*http.Transport).TLSClientConfig == nil {
		config.Transport.(*http.Transport).TLSClientConfig = &tls.Config{}
	}
	return config.Transport.(*http.Transport).TLSClientConfig
}

func (a *ApiClient) GetESClient() *elasticsearch.Client {
	return a.es
}

func (a *ApiClient) ID(ctx context.Context, resourceId string) (*CompositeId, diag.Diagnostics) {
	var diags diag.Diagnostics
	clusterId, diags := a.ClusterID(ctx)
	if diags.HasError() {
		return nil, diags
	}
	return &CompositeId{*clusterId, resourceId}, diags
}

func (a *ApiClient) serverInfo(ctx context.Context) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, err := a.es.Info(a.es.Info.WithContext(ctx))
	if err != nil {
		return nil, diag.FromErr(err)
	}
	defer res.Body.Close()
	if diags := utils.CheckError(res, "Unable to connect to the Elasticsearch cluster"); diags.HasError() {
		return nil, diags
	}

	info := make(map[string]interface{})
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return nil, diag.FromErr(err)
	}

	return info, diags
}

func (a *ApiClient) ServerVersion(ctx context.Context) (*version.Version, diag.Diagnostics) {
	info, diags := a.serverInfo(ctx)
	if diags.HasError() {
		return nil, diags
	}

	rawVersion := info["version"].(map[string]interface{})["number"].(string)
	serverVersion, err := version.NewVersion(rawVersion)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	return serverVersion, nil
}

func (a *ApiClient) ClusterID(ctx context.Context) (*string, diag.Diagnostics) {
	info, diags := a.serverInfo(ctx)
	if diags.HasError() {
		return nil, diags
	}

	if uuid := info["cluster_uuid"].(string); uuid != "" && uuid != "_na_" {
		tflog.Trace(ctx, fmt.Sprintf("cluster UUID: %s", uuid))
		return &uuid, diags
	}

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Error,
		Summary:  "Unable to get cluster UUID",
		Detail: `Unable to get cluster UUID.
		There might be a problem with permissions or cluster is still starting up and UUID has not been populated yet.`,
	})
	return nil, diags
}
