import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { ShieldQuestion } from "lucide-react";
import type { HostKeyPrompt } from "@/lib/hostKey";

/**
 * First-contact confirmation for an SSH host key.
 *
 * Shows the fingerprint in OpenSSH's format so it can be compared against
 * `ssh-keygen -lf` run on the host itself — the only check that actually means
 * anything here. Once confirmed the key is pinned and later connections are
 * verified without asking again.
 */
export function HostKeyPromptDialog({
  prompt,
  onDecision,
}: {
  prompt: HostKeyPrompt | null;
  onDecision: (accepted: boolean) => void;
}) {
  return (
    <AlertDialog open={!!prompt} onOpenChange={(open) => !open && onDecision(false)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <ShieldQuestion className="h-5 w-5 text-[hsl(var(--neon-cyan))]" />
            Trust this host?
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-3">
              <p>
                First connection to{" "}
                <span className="font-mono text-foreground">
                  {prompt?.host}:{prompt?.port}
                </span>
                . Its identity has not been recorded yet.
              </p>
              <div className="rounded-md border border-border bg-muted/50 p-3 space-y-1">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  {prompt?.algorithm} fingerprint
                </p>
                <p className="font-mono text-xs break-all text-foreground">{prompt?.fingerprint}</p>
              </div>
              <p className="text-xs">
                Confirm it matches the host by running{" "}
                <code className="bg-muted px-1 py-0.5 rounded text-[11px]">
                  ssh-keygen -lf /etc/ssh/ssh_host_{prompt?.algorithm.replace("ssh-", "")}_key.pub
                </code>{" "}
                there. Accepting pins this key: if it ever changes, the connection is refused
                instead of silently trusted.
              </p>
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => onDecision(false)}>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => onDecision(true)}>Trust and connect</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
