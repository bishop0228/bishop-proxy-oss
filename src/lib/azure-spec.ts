/**
 * §1.17.18 Azure OpenAI api-key distinct-auth BYOK leg.
 *
 * NO operatorKeyVar — Azure is BYOK-only; managed mode fails closed
 * (azure_requires_byok, 400). Operator path is structurally unrepresentable.
 */

export interface AzureUpstreamSpec {
  hostSuffix: string;
  baseUrlVar: string;
}

export const AZURE_UPSTREAM: AzureUpstreamSpec = {
  hostSuffix: ".openai.azure.com",
  baseUrlVar: "AZURE_BASE_URL",
};
