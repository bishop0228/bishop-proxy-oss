/**
 * §1.17.17 AWS Bedrock SigV4 distinct-auth BYOK leg.
 *
 * NO operatorKeyVar — Bedrock is BYOK-only; managed mode fails closed
 * (bedrock_requires_byok, 400). Operator path is structurally unrepresentable.
 */

export interface BedrockUpstreamSpec {
  upstreamHost: string;
  region: string;
  service: string;
  baseUrlVar: string;
}

export const BEDROCK_UPSTREAM: BedrockUpstreamSpec = {
  upstreamHost: "bedrock-runtime.us-east-1.amazonaws.com",
  region: "us-east-1",
  service: "bedrock-runtime",
  baseUrlVar: "BEDROCK_BASE_URL",
};
