export function isToolInScope(tool: string, tools: ReadonlyArray<string>): boolean {
  return tools.includes(tool);
}

export function uniqueTypes(labels: ReadonlyArray<string>): string[] {
  const types = new Set<string>();
  for (const label of labels) {
    types.add(label.replace(/_\d+$/, ""));
  }
  return Array.from(types);
}
