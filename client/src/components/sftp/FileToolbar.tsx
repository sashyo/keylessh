import { useRef } from "react";
import {
  Upload,
  FolderPlus,
  RefreshCw,
  Trash2,
  Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface FileToolbarProps {
  onUpload: (files: FileList) => void;
  onNewFolder: () => void;
  onRefresh: () => void;
  onDelete?: () => void;
  onDownload?: () => void;
  selectedCount: number;
  loading?: boolean;
  className?: string;
}

export function FileToolbar({
  onUpload,
  onNewFolder,
  onRefresh,
  onDelete,
  onDownload,
  selectedCount,
  loading,
  className,
}: FileToolbarProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      onUpload(files);
      e.target.value = "";
    }
  };

  return (
    <TooltipProvider delayDuration={300}>
      <div className={cn("flex items-center gap-1 p-1", className)}>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={handleFileChange}
        />

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={handleUploadClick}
            >
              <Upload className="h-4 w-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Upload files</TooltipContent>
        </Tooltip>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={onNewFolder}
            >
              <FolderPlus className="h-4 w-4" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>New folder</TooltipContent>
        </Tooltip>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={onRefresh}
              disabled={loading}
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Refresh</TooltipContent>
        </Tooltip>

        {selectedCount > 0 && (
          <>
            <Separator orientation="vertical" className="h-5 mx-1" />

            {selectedCount === 1 && onDownload && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={onDownload}
                  >
                    <Download className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download</TooltipContent>
              </Tooltip>
            )}

            {onDelete && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-destructive hover:text-destructive"
                    onClick={onDelete}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  Delete {selectedCount > 1 ? `${selectedCount} items` : ""}
                </TooltipContent>
              </Tooltip>
            )}

            <span className="text-xs text-muted-foreground ml-1">
              {selectedCount} selected
            </span>
          </>
        )}
      </div>
    </TooltipProvider>
  );
}
