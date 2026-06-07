/** Typed accessor for dynamic env-var-name lookup (e.g. spec.baseUrlVar).
 *  Centralizes the one unavoidable cast so route files stay type-clean. */
export function envVar(env: unknown, key: string): string | undefined {
  return (env as Record<string, string | undefined>)[key];
}
