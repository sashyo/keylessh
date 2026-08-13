import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Trash2 } from "lucide-react";
import {
  parseBackends,
  serializeBackends,
  backendProtocol,
  EMPTY_BACKEND,
  type BackendRow,
} from "@/lib/backends";

/**
 * Edit backends as rows instead of the `Name=url;flags` string the gateway
 * stores.
 *
 * Rows are held here rather than derived from the string on each render. A row
 * being filled in is not yet a valid backend, and the string cannot represent
 * one — serializing drops it — so deriving would delete a new row the moment it
 * was added. The string is still what gets saved: every edit serializes the
 * complete rows back out through onChange.
 */
export function BackendsEditor({
  value,
  onChange,
}: {
  value: string;
  onChange: (backends: string) => void;
}) {
  const [rows, setRows] = useState<BackendRow[]>(() => parseBackends(value));
  const [raw, setRaw] = useState(false);

  const commit = (next: BackendRow[]) => {
    setRows(next);
    onChange(serializeBackends(next));
  };

  const update = (index: number, patch: Partial<BackendRow>) =>
    commit(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));

  const add = () => commit([...rows, { ...EMPTY_BACKEND }]);
  const remove = (index: number) => commit(rows.filter((_, i) => i !== index));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label className="text-xs">Backends <span className="text-muted-foreground font-normal">(optional)</span></Label>
        <button
          type="button"
          onClick={() => {
            if (raw) setRows(parseBackends(value)); // adopt whatever was typed
            setRaw(!raw);
          }}
          className="text-[10px] text-muted-foreground hover:text-foreground underline underline-offset-2"
        >
          {raw ? "Edit as rows" : "Edit as text"}
        </button>
      </div>

      {raw ? (
        <Input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Name=rdp://host:3389;eddsa"
          className="font-mono text-xs"
        />
      ) : (
        <div className="space-y-2">
          {rows.map((row, i) => (
            <div key={i} className="rounded-md border border-border p-2 space-y-2">
              <div className="flex gap-2">
                <Input
                  value={row.name}
                  onChange={(e) => update(i, { name: e.target.value })}
                  placeholder="Name"
                  className="h-8 text-xs w-1/3"
                />
                <Input
                  value={row.url}
                  onChange={(e) => update(i, { url: e.target.value })}
                  placeholder="ssh://10.0.0.9:22"
                  className="h-8 text-xs flex-1 font-mono"
                />
                <Badge variant="outline" className="h-8 px-2 text-[10px] uppercase shrink-0 flex items-center">
                  {backendProtocol(row.url)}
                </Badge>
                <Button type="button" size="icon" variant="ghost" className="h-8 w-8 shrink-0" onClick={() => remove(i)}>
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 pl-1">
                {([
                  ["eddsa", "EdDSA", "Passwordless RDP using EdDSA certificates"],
                  ["noAuth", "No auth", "Skip JWT verification for this backend"],
                  ["stripAuth", "Strip auth", "Remove auth headers before forwarding"],
                ] as const).map(([key, label, title]) => (
                  <label key={key} className="flex items-center gap-1.5 text-[11px] text-muted-foreground" title={title}>
                    <input
                      type="checkbox"
                      checked={row[key]}
                      onChange={(e) => update(i, { [key]: e.target.checked })}
                      className="h-3 w-3 accent-[hsl(var(--neon-cyan))]"
                    />
                    {label}
                  </label>
                ))}
              </div>
            </div>
          ))}

          <Button type="button" variant="outline" size="sm" className="w-full gap-1.5 h-8 text-xs" onClick={add}>
            <Plus className="h-3.5 w-3.5" /> Add backend
          </Button>
        </div>
      )}

      <p className="text-[10px] text-muted-foreground">
        Pre-configured endpoints. Leave empty to use custom IP connections only.
      </p>
    </div>
  );
}
