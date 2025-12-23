import { useState, useCallback } from "react";
import type { SftpClient, SftpFileInfo } from "@/lib/sftp";
import { useSftp } from "@/hooks/useSftp";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PathBreadcrumb } from "./PathBreadcrumb";
import { FileToolbar } from "./FileToolbar";
import { FileList } from "./FileList";
import { NewFolderDialog } from "./NewFolderDialog";
import { RenameDialog } from "./RenameDialog";
import { PropertiesDialog } from "./PropertiesDialog";
import { DeleteConfirmDialog } from "./DeleteConfirmDialog";
import { cn } from "@/lib/utils";
import { AlertCircle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface FileBrowserProps {
  client: SftpClient | null;
  initialPath?: string;
  className?: string;
}

export function FileBrowser({ client, initialPath = "~", className }: FileBrowserProps) {
  const {
    currentPath,
    entries,
    loading,
    error,
    navigateTo,
    refresh,
    download,
    upload,
    remove,
    rename,
    mkdir,
    chmod,
    selectedPaths,
    toggleSelection,
    clearSelection,
  } = useSftp({ client, initialPath });

  // Dialog states
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [propertiesOpen, setPropertiesOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  // Current item for dialogs
  const [currentItem, setCurrentItem] = useState<SftpFileInfo | null>(null);

  const handleOpen = useCallback(
    async (entry: SftpFileInfo) => {
      if (entry.type === "directory") {
        await navigateTo(entry.path);
      } else {
        // Download file
        try {
          const blob = await download(entry.path);
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = entry.name;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        } catch (err) {
          console.error("Download failed:", err);
        }
      }
    },
    [navigateTo, download]
  );

  const handleDownload = useCallback(
    async (entry: SftpFileInfo) => {
      if (entry.type === "directory") return;

      try {
        const blob = await download(entry.path);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = entry.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (err) {
        console.error("Download failed:", err);
      }
    },
    [download]
  );

  const handleUpload = useCallback(
    async (files: FileList) => {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        try {
          await upload(file);
        } catch (err) {
          console.error(`Upload failed for ${file.name}:`, err);
        }
      }
    },
    [upload]
  );

  const handleRename = useCallback((entry: SftpFileInfo) => {
    setCurrentItem(entry);
    setRenameOpen(true);
  }, []);

  const handleDelete = useCallback((entry: SftpFileInfo) => {
    setCurrentItem(entry);
    setDeleteOpen(true);
  }, []);

  const handleProperties = useCallback((entry: SftpFileInfo) => {
    setCurrentItem(entry);
    setPropertiesOpen(true);
  }, []);

  const handleCopyPath = useCallback((entry: SftpFileInfo) => {
    navigator.clipboard.writeText(entry.path);
  }, []);

  const handleDeleteConfirm = useCallback(async () => {
    if (currentItem) {
      await remove(currentItem.path);
    }
  }, [currentItem, remove]);

  const handleBulkDelete = useCallback(() => {
    const firstSelected = entries.find((e) => selectedPaths.has(e.path));
    if (firstSelected) {
      setCurrentItem(firstSelected);
      setDeleteOpen(true);
    }
  }, [entries, selectedPaths]);

  const handleBulkDownload = useCallback(async () => {
    const selected = entries.filter((e) => selectedPaths.has(e.path) && e.type !== "directory");
    if (selected.length === 1) {
      await handleDownload(selected[0]);
    }
  }, [entries, selectedPaths, handleDownload]);

  const selectedCount = selectedPaths.size;
  const selectedFile =
    selectedCount === 1
      ? entries.find((e) => selectedPaths.has(e.path) && e.type !== "directory")
      : null;

  return (
    <div className={cn("flex flex-col h-full bg-background", className)}>
      {/* Toolbar */}
      <FileToolbar
        onUpload={handleUpload}
        onNewFolder={() => setNewFolderOpen(true)}
        onRefresh={refresh}
        onDelete={selectedCount > 0 ? handleBulkDelete : undefined}
        onDownload={selectedFile ? handleBulkDownload : undefined}
        selectedCount={selectedCount}
        loading={loading}
        className="border-b"
      />

      {/* Path breadcrumb */}
      <PathBreadcrumb
        path={currentPath}
        onNavigate={navigateTo}
        className="px-2 py-1 border-b bg-muted/30"
      />

      {/* Error alert */}
      {error && (
        <Alert variant="destructive" className="m-2">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* File list */}
      <ScrollArea className="flex-1">
        <FileList
          entries={entries}
          selectedPaths={selectedPaths}
          onSelect={toggleSelection}
          onOpen={handleOpen}
          onDownload={handleDownload}
          onRename={handleRename}
          onDelete={handleDelete}
          onProperties={handleProperties}
          onCopyPath={handleCopyPath}
          loading={loading}
        />
      </ScrollArea>

      {/* Dialogs */}
      <NewFolderDialog
        open={newFolderOpen}
        onOpenChange={setNewFolderOpen}
        onConfirm={mkdir}
      />

      <RenameDialog
        open={renameOpen}
        onOpenChange={setRenameOpen}
        currentName={currentItem?.name ?? ""}
        currentPath={currentItem?.path ?? ""}
        onConfirm={rename}
      />

      <PropertiesDialog
        open={propertiesOpen}
        onOpenChange={setPropertiesOpen}
        file={currentItem}
        onChmod={chmod}
      />

      <DeleteConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        itemName={currentItem?.name ?? ""}
        itemCount={selectedCount > 1 ? selectedCount : 1}
        onConfirm={handleDeleteConfirm}
      />
    </div>
  );
}
