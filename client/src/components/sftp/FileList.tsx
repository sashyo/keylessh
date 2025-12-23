import { useCallback } from "react";
import type { SftpFileInfo } from "@/lib/sftp";
import { formatFileSize } from "@/lib/sftp";
import { FileIcon } from "./FileIcon";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
  Download,
  Pencil,
  Trash2,
  Info,
  FolderOpen,
  Copy,
} from "lucide-react";

interface FileListProps {
  entries: SftpFileInfo[];
  selectedPaths: Set<string>;
  onSelect: (path: string) => void;
  onOpen: (entry: SftpFileInfo) => void;
  onDownload: (entry: SftpFileInfo) => void;
  onRename: (entry: SftpFileInfo) => void;
  onDelete: (entry: SftpFileInfo) => void;
  onProperties: (entry: SftpFileInfo) => void;
  onCopyPath: (entry: SftpFileInfo) => void;
  loading?: boolean;
  className?: string;
}

interface FileRowProps {
  entry: SftpFileInfo;
  isSelected: boolean;
  onSelect: () => void;
  onOpen: () => void;
  onDownload: () => void;
  onRename: () => void;
  onDelete: () => void;
  onProperties: () => void;
  onCopyPath: () => void;
}

function FileRow({
  entry,
  isSelected,
  onSelect,
  onOpen,
  onDownload,
  onRename,
  onDelete,
  onProperties,
  onCopyPath,
}: FileRowProps) {
  const handleDoubleClick = () => {
    onOpen();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      onOpen();
    }
  };

  const formattedDate = entry.modifiedAt
    ? entry.modifiedAt.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "-";

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <div
          className={cn(
            "flex items-center gap-2 px-2 py-1 cursor-default select-none rounded-sm",
            "hover:bg-accent/50 focus:bg-accent focus:outline-none",
            isSelected && "bg-accent"
          )}
          tabIndex={0}
          onDoubleClick={handleDoubleClick}
          onKeyDown={handleKeyDown}
        >
          <Checkbox
            checked={isSelected}
            onCheckedChange={() => onSelect()}
            onClick={(e) => e.stopPropagation()}
            className="shrink-0"
          />

          <FileIcon name={entry.name} type={entry.type} className="shrink-0" />

          <span className="flex-1 truncate text-sm">{entry.name}</span>

          <span className="text-xs text-muted-foreground w-20 text-right shrink-0">
            {entry.type === "directory" ? "-" : formatFileSize(entry.size)}
          </span>

          <span className="text-xs text-muted-foreground font-mono w-20 shrink-0">
            {entry.permissionsString}
          </span>

          <span className="text-xs text-muted-foreground w-32 text-right shrink-0 hidden lg:block">
            {formattedDate}
          </span>
        </div>
      </ContextMenuTrigger>

      <ContextMenuContent>
        <ContextMenuItem onClick={onOpen}>
          <FolderOpen className="mr-2 h-4 w-4" />
          {entry.type === "directory" ? "Open" : "Download"}
        </ContextMenuItem>

        {entry.type !== "directory" && (
          <ContextMenuItem onClick={onDownload}>
            <Download className="mr-2 h-4 w-4" />
            Download
          </ContextMenuItem>
        )}

        <ContextMenuSeparator />

        <ContextMenuItem onClick={onCopyPath}>
          <Copy className="mr-2 h-4 w-4" />
          Copy path
        </ContextMenuItem>

        <ContextMenuItem onClick={onRename}>
          <Pencil className="mr-2 h-4 w-4" />
          Rename
        </ContextMenuItem>

        <ContextMenuItem onClick={onProperties}>
          <Info className="mr-2 h-4 w-4" />
          Properties
        </ContextMenuItem>

        <ContextMenuSeparator />

        <ContextMenuItem
          onClick={onDelete}
          className="text-destructive focus:text-destructive"
        >
          <Trash2 className="mr-2 h-4 w-4" />
          Delete
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

export function FileList({
  entries,
  selectedPaths,
  onSelect,
  onOpen,
  onDownload,
  onRename,
  onDelete,
  onProperties,
  onCopyPath,
  loading,
  className,
}: FileListProps) {
  const filteredEntries = entries.filter(
    (e) => e.name !== "." && e.name !== ".."
  );

  const handleSelectAll = useCallback(() => {
    // Handled by parent
  }, []);

  if (loading) {
    return (
      <div className={cn("flex items-center justify-center py-8", className)}>
        <div className="text-sm text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (filteredEntries.length === 0) {
    return (
      <div className={cn("flex items-center justify-center py-8", className)}>
        <div className="text-sm text-muted-foreground">Empty directory</div>
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col", className)}>
      {/* Header */}
      <div className="flex items-center gap-2 px-2 py-1 border-b text-xs font-medium text-muted-foreground">
        <div className="w-4 shrink-0" /> {/* Checkbox placeholder */}
        <div className="w-4 shrink-0" /> {/* Icon placeholder */}
        <div className="flex-1">Name</div>
        <div className="w-20 text-right shrink-0">Size</div>
        <div className="w-20 shrink-0">Permissions</div>
        <div className="w-32 text-right shrink-0 hidden lg:block">Modified</div>
      </div>

      {/* File rows */}
      <div className="flex-1 overflow-auto">
        {filteredEntries.map((entry) => (
          <FileRow
            key={entry.path}
            entry={entry}
            isSelected={selectedPaths.has(entry.path)}
            onSelect={() => onSelect(entry.path)}
            onOpen={() => onOpen(entry)}
            onDownload={() => onDownload(entry)}
            onRename={() => onRename(entry)}
            onDelete={() => onDelete(entry)}
            onProperties={() => onProperties(entry)}
            onCopyPath={() => onCopyPath(entry)}
          />
        ))}
      </div>
    </div>
  );
}
