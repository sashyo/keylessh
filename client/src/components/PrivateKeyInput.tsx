import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Key, Loader2, AlertCircle } from "lucide-react";

interface PrivateKeyInputProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: () => void;
  serverName: string;
  username: string;
  tidePublicKey?: string | null;
  isConnecting?: boolean;
  error?: string | null;
}

export function PrivateKeyInput({
  open,
  onOpenChange,
  onSubmit,
  serverName,
  username,
  tidePublicKey = null,
  isConnecting = false,
  error = null,
}: PrivateKeyInputProps) {
  const handleSubmit = () => {
    onSubmit();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && e.ctrlKey) {
      handleSubmit();
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg" onKeyDown={handleKeyDown}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Connect to SSH
          </DialogTitle>
          <DialogDescription>
            Connect as <strong>{username}</strong> to <strong>{serverName}</strong> using Tide.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Alert>
            <AlertDescription>
              Uses your Tide session key to sign the SSH authentication challenge.
              Your private key is securely managed by Tide's distributed enclave network.
            </AlertDescription>
          </Alert>

          <p className="text-sm text-muted-foreground">
            Your SSH server must trust the Tide public key for this user (add it to <span className="font-mono">authorized_keys</span>).
          </p>

          {tidePublicKey && (
            <div className="space-y-2">
              <Label>Tide SSH public key</Label>
              <div className="flex items-start gap-2">
                <Textarea
                  value={tidePublicKey}
                  readOnly
                  className="font-mono text-xs h-24 resize-none"
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={isConnecting}
                  onClick={() => navigator.clipboard.writeText(tidePublicKey)}
                >
                  Copy
                </Button>
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isConnecting}
          >
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isConnecting}>
            {isConnecting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Connecting...
              </>
            ) : (
              "Connect with Tide"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
