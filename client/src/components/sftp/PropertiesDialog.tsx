import { useState, useEffect } from "react";
import type { SftpFileInfo } from "@/lib/sftp";
import { formatFileSize } from "@/lib/sftp";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { FileIcon } from "./FileIcon";

interface PropertiesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  file: SftpFileInfo | null;
  onChmod: (path: string, mode: number) => Promise<void>;
}

interface PermissionBit {
  label: string;
  bit: number;
}

const ownerBits: PermissionBit[] = [
  { label: "Read", bit: 0o400 },
  { label: "Write", bit: 0o200 },
  { label: "Execute", bit: 0o100 },
];

const groupBits: PermissionBit[] = [
  { label: "Read", bit: 0o040 },
  { label: "Write", bit: 0o020 },
  { label: "Execute", bit: 0o010 },
];

const otherBits: PermissionBit[] = [
  { label: "Read", bit: 0o004 },
  { label: "Write", bit: 0o002 },
  { label: "Execute", bit: 0o001 },
];

export function PropertiesDialog({
  open,
  onOpenChange,
  file,
  onChmod,
}: PropertiesDialogProps) {
  const [permissions, setPermissions] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [octalInput, setOctalInput] = useState("");

  useEffect(() => {
    if (file) {
      setPermissions(file.permissions);
      setOctalInput(file.permissions.toString(8).padStart(3, "0"));
      setError(null);
    }
  }, [file, open]);

  const toggleBit = (bit: number) => {
    const newPerms = permissions ^ bit;
    setPermissions(newPerms);
    setOctalInput(newPerms.toString(8).padStart(3, "0"));
  };

  const handleOctalChange = (value: string) => {
    setOctalInput(value);
    const num = parseInt(value, 8);
    if (!isNaN(num) && num >= 0 && num <= 0o777) {
      setPermissions(num);
    }
  };

  const handleSubmit = async () => {
    if (!file) return;

    if (permissions === file.permissions) {
      onOpenChange(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await onChmod(file.path, permissions);
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change permissions");
    } finally {
      setLoading(false);
    }
  };

  if (!file) return null;

  const formattedDate = file.modifiedAt
    ? file.modifiedAt.toLocaleString()
    : "Unknown";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileIcon name={file.name} type={file.type} />
            {file.name}
          </DialogTitle>
          <DialogDescription>{file.path}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Basic Info */}
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="text-muted-foreground">Type</div>
            <div className="capitalize">{file.type}</div>

            <div className="text-muted-foreground">Size</div>
            <div>{file.type === "directory" ? "-" : formatFileSize(file.size)}</div>

            <div className="text-muted-foreground">Modified</div>
            <div>{formattedDate}</div>

            <div className="text-muted-foreground">Owner</div>
            <div>{file.owner}</div>

            <div className="text-muted-foreground">Group</div>
            <div>{file.group}</div>
          </div>

          {/* Permissions */}
          <div className="space-y-3">
            <Label>Permissions</Label>

            <div className="flex items-center gap-2">
              <Input
                value={octalInput}
                onChange={(e) => handleOctalChange(e.target.value)}
                className="w-20 font-mono"
                maxLength={4}
                disabled={loading}
              />
              <span className="text-sm text-muted-foreground font-mono">
                {permissions.toString(8).padStart(3, "0")}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-4 text-sm">
              <div className="space-y-2">
                <div className="font-medium">Owner</div>
                {ownerBits.map(({ label, bit }) => (
                  <div key={bit} className="flex items-center gap-2">
                    <Checkbox
                      checked={(permissions & bit) !== 0}
                      onCheckedChange={() => toggleBit(bit)}
                      disabled={loading}
                    />
                    <span>{label}</span>
                  </div>
                ))}
              </div>

              <div className="space-y-2">
                <div className="font-medium">Group</div>
                {groupBits.map(({ label, bit }) => (
                  <div key={bit} className="flex items-center gap-2">
                    <Checkbox
                      checked={(permissions & bit) !== 0}
                      onCheckedChange={() => toggleBit(bit)}
                      disabled={loading}
                    />
                    <span>{label}</span>
                  </div>
                ))}
              </div>

              <div className="space-y-2">
                <div className="font-medium">Others</div>
                {otherBits.map(({ label, bit }) => (
                  <div key={bit} className="flex items-center gap-2">
                    <Checkbox
                      checked={(permissions & bit) !== 0}
                      onCheckedChange={() => toggleBit(bit)}
                      disabled={loading}
                    />
                    <span>{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={loading}>
            {loading ? "Saving..." : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
