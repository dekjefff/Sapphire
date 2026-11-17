// Intentionally vulnerable scanner fixture. Never invoke this function.
export function evaluateUntrustedInput(untrustedInput) {
  return eval(untrustedInput);
}
