export interface SourceLocation {
  filePath: string;
  line: number;
  column: number;
}

export function formatSourceLocation(location: SourceLocation): string {
  return `${location.filePath}:${location.line}:${location.column}`;
}
