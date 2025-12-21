import { useState, useRef, useCallback } from "react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Key, Upload, Loader2, AlertCircle } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface PrivateKeyInputProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (args: { mode: "pem"; privateKey: string; passphrase?: string } | { mode: "tide" }) => void;
  serverName: string;
  username: string;
  tidePublicKey?: string | null;
  isConnecting?: boolean;
  error?: string | null;
}

const SESSION_STORAGE_KEY = "ssh_private_key";

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
  const [mode, setMode] = useState<"tide" | "pem">("tide");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [rememberKey, setRememberKey] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Try to load key from session storage on mount
  useState(() => {
    const savedKey = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (savedKey) {
      setPrivateKey(savedKey);
      setRememberKey(true);
    }
  });

  const validateKey = (key: string): boolean => {
    const trimmed = key.trim();

    // Check for common PEM markers
    const validMarkers = [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ];

    const hasValidStart = validMarkers.some((marker) =>
      trimmed.startsWith(marker)
    );
    const hasValidEnd = trimmed.includes("-----END");

    return hasValidStart && hasValidEnd;
  };

  const handleKeyChange = (value: string) => {
    setPrivateKey(value);
    setValidationError(null);
  };

  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setPrivateKey(content);
        setValidationError(null);
      };
      reader.onerror = () => {
        setValidationError("Failed to read file");
      };
      reader.readAsText(file);

      // Reset input so same file can be selected again
      event.target.value = "";
    },
    []
  );

  const handleSubmit = () => {
    if (mode === "tide") {
      onSubmit({ mode: "tide" });
      return;
    }

    const trimmedKey = privateKey.trim();

    if (!trimmedKey) {
      setValidationError("Please enter or upload a private key");
      return;
    }

    if (!validateKey(trimmedKey)) {
      setValidationError(
        "Invalid private key format. Key should be in PEM format (starting with -----BEGIN ... PRIVATE KEY-----)"
      );
      return;
    }

    // Save to session storage if requested
    if (rememberKey) {
      sessionStorage.setItem(SESSION_STORAGE_KEY, trimmedKey);
    } else {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }

    onSubmit({ mode: "pem", privateKey: trimmedKey, passphrase: passphrase || undefined });
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
            Connect as <strong>{username}</strong> to <strong>{serverName}</strong>.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {(error || validationError) && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error || validationError}</AlertDescription>
            </Alert>
          )}

          <Tabs value={mode} onValueChange={(v) => setMode(v as "tide" | "pem")}>
            <TabsList className="grid grid-cols-2 w-full">
              <TabsTrigger value="tide" disabled={isConnecting}>
                Tide Key
              </TabsTrigger>
              <TabsTrigger value="pem" disabled={isConnecting}>
                Private Key
              </TabsTrigger>
            </TabsList>

            <TabsContent value="tide" className="mt-4 space-y-3">
              <Alert>
                <AlertDescription>
                  Uses your Tide session key to sign the SSH authentication challenge. No private key is pasted into the browser.
                </AlertDescription>
              </Alert>
              <p className="text-sm text-muted-foreground">
                Your SSH server must trust the Tide public key for this client/user (add it to <span className="font-mono">authorized_keys</span>).
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
            </TabsContent>

            <TabsContent value="pem" className="mt-4 space-y-4">
              <Alert>
                <AlertDescription>
                  Your key stays in the browser and is never sent to our servers.
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="privateKey">Private Key (PEM format)</Label>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isConnecting}
                  >
                    <Upload className="h-4 w-4 mr-2" />
                    Upload File
                  </Button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pem,.key,id_rsa,id_ed25519,id_ecdsa,id_dsa"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </div>
                <Textarea
                  id="privateKey"
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
                  value={privateKey}
                  onChange={(e) => handleKeyChange(e.target.value)}
                  className="font-mono text-xs h-48 resize-none"
                  disabled={isConnecting}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="passphrase">
                  Passphrase (optional, for encrypted keys)
                </Label>
                <Input
                  id="passphrase"
                  type="password"
                  placeholder="Enter passphrase if key is encrypted"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  disabled={isConnecting}
                />
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="rememberKey"
                  checked={rememberKey}
                  onCheckedChange={(checked) => setRememberKey(checked === true)}
                  disabled={isConnecting}
                />
                <Label
                  htmlFor="rememberKey"
                  className="text-sm font-normal cursor-pointer"
                >
                  Remember key for this session (cleared when tab closes)
                </Label>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isConnecting}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={isConnecting || (mode === "pem" && !privateKey)}
          >
            {isConnecting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Connecting...
              </>
            ) : (
              mode === "tide" ? "Connect with Tide" : "Connect"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
