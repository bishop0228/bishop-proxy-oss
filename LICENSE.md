# Business Source License 1.1

## License

**Licensor:** Bishop AI LLC

**Licensed Work:** bishop-proxy — the inference proxy software in this
repository, including all source code, documentation, configuration files,
and associated materials. The Licensed Work is © 2026 Bishop AI LLC.

**Additional Use Grant:** You may use the Licensed Work for any
non-production purpose, including:

- Reading, studying, and auditing the source code
- Running the Worker locally via `wrangler dev` against a local test endpoint
  to evaluate behavior
- Inspecting the outbound-allowlist enforcement
  (`src/lib/outbound-allowlist.ts` and its test suite) to verify the
  no-exfiltration-surface claim made in the README
- Academic research and security analysis
- Internal evaluation to determine whether to adopt Bishop
- Testing and development in non-production environments

**Production use** means operating the Licensed Work, or any substantial
portion of it, to build or operate a competing product as defined below.
Running bishop-proxy locally for your own personal evaluation is permitted
and is not production use under this license.

**Change Date:** April 16, 2030

**Change License:** Apache License, Version 2.0

---

## Terms

The Licensor hereby grants you the right to copy, modify, create derivative
works, redistribute, and make non-production use of the Licensed Work.

If your use of the Licensed Work does not comply with the requirements
currently in effect as described in this License, you must purchase a
commercial license from the Licensor, its affiliated entities, or
authorized resellers, or you must refrain from using the Licensed Work.

All copies of the original and modified Licensed Work, and derivative works
of the Licensed Work, are subject to this License. This License applies
separately for each version of the Licensed Work and the Change Date may
vary for each version of the Licensed Work released by the Licensor.

You must conspicuously display this License on each original or modified
copy of the Licensed Work. If you receive the Licensed Work in original or
modified form from a third party, the terms and conditions set forth in
this License apply to your use of that work.

Any use of the Licensed Work in violation of this License will automatically
terminate your rights under this License for the current and all other
versions of the Licensed Work.

This License does not grant you any right in any trademark or logo of the
Licensor or its affiliates (provided that you may use a trademark or logo
of the Licensor as expressly required by this License).

TO THE EXTENT PERMITTED BY APPLICABLE LAW, THE LICENSED WORK IS PROVIDED ON
AN "AS IS" BASIS. LICENSOR HEREBY DISCLAIMS ALL WARRANTIES AND CONDITIONS,
EXPRESS OR IMPLIED, INCLUDING (WITHOUT LIMITATION) WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND
TITLE.

---

## Competing Products Restriction

You may not use the Licensed Work, or any substantial portion of it, to
build, operate, or distribute a product or service that competes with
bishop-proxy. A **competing product** is software that:

1. Operates as an inference-forwarding proxy with server-enforced per-user
   quota, tier verification, and outbound-allowlist enforcement, **and**
2. Is deployed as part of an AI automation agent product or service that
   uses kernel-level enforcement (including but not limited to Landlock,
   seccomp, AppArmor, SELinux, or equivalent OS-level sandboxing) on the
   client side as a security boundary

A product that satisfies only one of these conditions is not a competing
product under this license. General-purpose API gateways, inference proxies
that do not include quota / tier / outbound-allowlist enforcement, and AI
automation agents that do not use a server-side inference proxy are not
competing products.

This restriction applies during the license term (before the Change Date).
After the Change Date, the Licensed Work converts to the Change License and
this restriction no longer applies.

---

## Patent Grant

Subject to the terms and conditions of this License, the Licensor hereby
grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
irrevocable patent license to make, have made, use, offer to sell, sell,
import, and otherwise transfer the Licensed Work, where such license
applies only to those patent claims licensable by the Licensor that are
necessarily infringed by the Licensed Work.

If you institute patent litigation against any entity (including a
cross-claim or counterclaim in a lawsuit) alleging that the Licensed Work
constitutes direct or contributory patent infringement, then any patent
licenses granted to you under this License for that Licensed Work shall
terminate as of the date such litigation is filed.

---

## Liability Limitation

IN NO EVENT SHALL THE LICENSOR BE LIABLE FOR ANY INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE LICENSED
WORK, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

THE LICENSOR'S TOTAL LIABILITY UNDER THIS LICENSE SHALL NOT EXCEED THE
AMOUNT YOU PAID THE LICENSOR FOR THE LICENSED WORK IN THE TWELVE (12)
MONTHS PRECEDING THE CLAIM, OR ONE HUNDRED DOLLARS ($100), WHICHEVER IS
GREATER.

---

## Governing Law

This License shall be governed by and construed in accordance with the
laws of the State of Wyoming, United States of America, without regard to
its conflict of laws provisions. Any legal action arising under this
License shall be brought exclusively in the federal or state courts located
in Sheridan County, Wyoming.

---

## Security Audit Carveout

Notwithstanding any other provision of this License, security researchers,
penetration testers, and auditors may use the Licensed Work for the purpose
of identifying and reporting security vulnerabilities, at their own risk,
provided that:

1. The use is limited to security research and vulnerability assessment
2. Any vulnerabilities discovered are reported to the Licensor in
   accordance with the project's security policy (SECURITY.md) before
   public disclosure
3. The researcher does not use the Licensed Work or knowledge gained from
   it to build a competing product as defined above

---

## Exception: Outbound-Allowlist Enforcement Files

The files `src/lib/outbound-allowlist.ts` and `tests/outbound-allowlist.test.ts`
are licensed under the Apache License, Version 2.0. See `LICENSE-APACHE.md`
for the full text. The Apache 2.0 license applies to those two files
regardless of the Change Date or any other provision of this Business Source
License.

---

## Notice

This license is based on the Business Source License 1.1, originally created
by MariaDB Corporation Ab. The original text is available at
https://mariadb.com/bsl11/. This adaptation has been modified by Bishop AI
LLC to include additional provisions specific to bishop-proxy.
